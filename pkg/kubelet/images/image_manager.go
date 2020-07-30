/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package images

import (
	"fmt"
	"time"

	dockerref "github.com/docker/distribution/reference"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/flowcontrol"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1alpha2"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/credentialprovider"
	credentialprovidersecrets "k8s.io/kubernetes/pkg/credentialprovider/secrets"
	kubecontainer "k8s.io/kubernetes/pkg/kubelet/container"
	"k8s.io/kubernetes/pkg/kubelet/events"
	"k8s.io/kubernetes/pkg/util/parsers"
)

// ensureSecretPulledImage - map of imageref (image digest) to successful secret pulled image details
var ensureSecretPulledImage map[string]*ensureSecretPulledImageDigest

type ensureSecretPulledImageDigest struct {
	// TODO: (mikebrow) time of last pull for this imageRef
	// TODO: (mikebrow) time of pull for each particular auth hash

	// map of auth hash (keys) used to successfully pull this imageref
	HashMatch map[string]bool
}

func init() {
	ensureSecretPulledImage = make(map[string]*ensureSecretPulledImageDigest)
}

// imageManager provides the functionalities for image pulling.
type imageManager struct {
	recorder     record.EventRecorder
	imageService kubecontainer.ImageService
	backOff      *flowcontrol.Backoff
	// It will check the presence of the image, and report the 'image pulling', image pulled' events correspondingly.
	puller  imagePuller
	keyring *credentialprovider.DockerKeyring
}

var _ ImageManager = &imageManager{}

// NewImageManager instantiates a new ImageManager object.
func NewImageManager(recorder record.EventRecorder, imageService kubecontainer.ImageService, imageBackOff *flowcontrol.Backoff, serialized bool, qps float32, burst int, keyring *credentialprovider.DockerKeyring) ImageManager {

	imageService = throttleImagePulling(imageService, qps, burst)

	var puller imagePuller
	if serialized {
		puller = newSerialImagePuller(imageService)
	} else {
		puller = newParallelImagePuller(imageService)
	}
	return &imageManager{
		recorder:     recorder,
		imageService: imageService,
		backOff:      imageBackOff,
		puller:       puller,
		keyring:      keyring,
	}
}

// shouldPullImage returns whether we should pull an image according to
// the presence and pull policy of the image.
func shouldPullImage(container *v1.Container, imagePresent, pulledBySecret, ensuredBySecret bool) bool {
	if container.ImagePullPolicy == v1.PullNever {
		return false
	}

	if container.ImagePullPolicy == v1.PullAlways {
		return true
	}

	if container.ImagePullPolicy == v1.PullIfNotPresent {
		if !imagePresent {
			return true
		}
		// if the imageRef has been pulled by a secret and Pull Policy is PullIfNotPresent
		// we need to ensure that the current pod's secrets map to an auth that has Already
		// pulled the image successfully. Otherwise pod B could use pod A's images
		// without auth. So in this case if pulledBySecret but not ensured by matching
		// secret auth for a pull again for the pod B scenario where the auth does not match
		if pulledBySecret && !ensuredBySecret {
			return true
		}
		return false
	}
	return false
}

// records an event using ref, event msg.  log to glog using prefix, msg, logFn
func (m *imageManager) logIt(ref *v1.ObjectReference, eventtype, event, prefix, msg string, logFn func(args ...interface{})) {
	if ref != nil {
		m.recorder.Event(ref, eventtype, event, msg)
	} else {
		logFn(fmt.Sprint(prefix, " ", msg))
	}
}

// EnsureImageExists pulls the image for the specified pod and container, and returns
// (imageRef, error message, error).
func (m *imageManager) EnsureImageExists(pod *v1.Pod, container *v1.Container, pullSecrets []v1.Secret, podSandboxConfig *runtimeapi.PodSandboxConfig) (string, string, error) {
	logPrefix := fmt.Sprintf("%s/%s/%s", pod.Namespace, pod.Name, container.Image)
	ref, err := kubecontainer.GenerateContainerRef(pod, container)
	if err != nil {
		klog.Errorf("Couldn't make a ref to pod %v, container %v: '%v'", pod.Name, container.Name, err)
	}

	// If the image contains no tag or digest, a default tag should be applied.
	image, err := applyDefaultImageTag(container.Image)
	if err != nil {
		msg := fmt.Sprintf("Failed to apply default image tag %q: %v", container.Image, err)
		m.logIt(ref, v1.EventTypeWarning, events.FailedToInspectImage, logPrefix, msg, klog.Warning)
		return "", msg, ErrInvalidImageName
	}

	var podAnnotations []kubecontainer.Annotation
	for k, v := range pod.GetAnnotations() {
		podAnnotations = append(podAnnotations, kubecontainer.Annotation{
			Name:  k,
			Value: v,
		})
	}

	spec := kubecontainer.ImageSpec{
		Image:       image,
		Annotations: podAnnotations,
	}
	imageRef, err := m.imageService.GetImageRef(spec)
	if err != nil {
		msg := fmt.Sprintf("Failed to inspect image %q: %v", container.Image, err)
		m.logIt(ref, v1.EventTypeWarning, events.FailedToInspectImage, logPrefix, msg, klog.Warning)
		return "", msg, ErrImageInspect
	}

	present := imageRef != ""

	pulledBySecret, ensuredBySecret := m.isEnsuredBySecret(imageRef, spec, pullSecrets)

	if !shouldPullImage(container, present, pulledBySecret, ensuredBySecret) {
		if present {
			msg := fmt.Sprintf("Container image %q already present on machine", container.Image)
			m.logIt(ref, v1.EventTypeNormal, events.PulledImage, logPrefix, msg, klog.Info)
			return imageRef, "", nil
		}
		msg := fmt.Sprintf("Container image %q is not present with pull policy of Never", container.Image)
		m.logIt(ref, v1.EventTypeWarning, events.ErrImageNeverPullPolicy, logPrefix, msg, klog.Warning)
		return "", msg, ErrImageNeverPull
	}

	backOffKey := fmt.Sprintf("%s_%s", pod.UID, container.Image)
	if m.backOff.IsInBackOffSinceUpdate(backOffKey, m.backOff.Clock.Now()) {
		msg := fmt.Sprintf("Back-off pulling image %q", container.Image)
		m.logIt(ref, v1.EventTypeNormal, events.BackOffPullImage, logPrefix, msg, klog.Info)
		return "", msg, ErrImagePullBackOff
	}
	m.logIt(ref, v1.EventTypeNormal, events.PullingImage, logPrefix, fmt.Sprintf("Pulling image %q", container.Image), klog.Info)
	startTime := time.Now()
	pullChan := make(chan pullResult)
	m.puller.pullImage(spec, pullSecrets, pullChan, podSandboxConfig)
	imagePullResult := <-pullChan
	if imagePullResult.err != nil {
		m.logIt(ref, v1.EventTypeWarning, events.FailedToPullImage, logPrefix, fmt.Sprintf("Failed to pull image %q: %v", container.Image, imagePullResult.err), klog.Warning)
		m.backOff.Next(backOffKey, m.backOff.Clock.Now())
		if imagePullResult.err == ErrRegistryUnavailable {
			msg := fmt.Sprintf("image pull failed for %s because the registry is unavailable.", container.Image)
			return "", msg, imagePullResult.err
		}

		return "", imagePullResult.err.Error(), ErrImagePull
	}
	m.logIt(ref, v1.EventTypeNormal, events.PulledImage, logPrefix, fmt.Sprintf("Successfully pulled image %q in %v", container.Image, time.Since(startTime)), klog.Info)
	m.backOff.GC()

	if imagePullResult.hash == "" {
		// successful pull no auth hash returned, auth was not required so we should reset the hashmap for this
		// imageref since auth is no longer required for the local image cache, allowing use of the ImageRef
		// by other pods if it remains cached and pull policy is PullIfNotPresent
		ensureSecretPulledImage[imageRef] = nil
	}
	// store/create hashMatch map entry for auth config hash key used to pull the image
	// for this imageref (digest)
	if imagePullResult.hash != "" {
		digest := ensureSecretPulledImage[imageRef]
		if digest == nil {
			digest = &ensureSecretPulledImageDigest{HashMatch: make(map[string]bool)}
			ensureSecretPulledImage[imageRef] = digest
		}
		digest.HashMatch[imagePullResult.hash] = true
	}

	return imagePullResult.imageRef, "", nil
}

// applyDefaultImageTag parses a docker image string, if it doesn't contain any tag or digest,
// a default tag will be applied.
func applyDefaultImageTag(image string) (string, error) {
	named, err := dockerref.ParseNormalizedNamed(image)
	if err != nil {
		return "", fmt.Errorf("couldn't parse image reference %q: %v", image, err)
	}
	_, isTagged := named.(dockerref.Tagged)
	_, isDigested := named.(dockerref.Digested)
	if !isTagged && !isDigested {
		// we just concatenate the image name with the default tag here instead
		// of using dockerref.WithTag(named, ...) because that would cause the
		// image to be fully qualified as docker.io/$name if it's a short name
		// (e.g. just busybox). We don't want that to happen to keep the CRI
		// agnostic wrt image names and default hostnames.
		image = image + ":latest"
	}
	return image, nil
}

// isEnsuredBySecret - returns true if the secret for an auth used to pull an
// image has already been authenticated through a successful pull request
// and the same auth exists for this podSandbox/image/
func (m *imageManager) isEnsuredBySecret(imageRef string, image kubecontainer.ImageSpec, pullSecrets []v1.Secret) (pulledBySecret, ensuredBySecret bool) {
	if imageRef == "" {
		return
	}
	if ensureSecretPulledImage[imageRef] != nil {
		pulledBySecret = true
	}

	img := image.Image
	repoToPull, _, _, err := parsers.ParseImageName(img)
	if err != nil {
		return
	}

	if m.keyring == nil {
		return
	}
	keyring, err := credentialprovidersecrets.MakeDockerKeyring(pullSecrets, *m.keyring)
	if err != nil {
		return
	}

	creds, withCredentials := keyring.Lookup(repoToPull)
	if !withCredentials {
		return
	}

	for _, currentCreds := range creds {
		auth := &runtimeapi.AuthConfig{
			Username:      currentCreds.Username,
			Password:      currentCreds.Password,
			Auth:          currentCreds.Auth,
			ServerAddress: currentCreds.ServerAddress,
			IdentityToken: currentCreds.IdentityToken,
			RegistryToken: currentCreds.RegistryToken,
		}

		hash := kubecontainer.HashAuth(auth)
		if hash != "" {
			digest := ensureSecretPulledImage[imageRef]
			if digest != nil {
				if digest.HashMatch[hash] {
					ensuredBySecret = true
					return
				}
			}
		}
	}
	return
}
