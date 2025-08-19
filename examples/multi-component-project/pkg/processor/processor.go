package processor

import (
	"fmt"

	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func ProcessData(data string) {
	fmt.Printf("Processing data: %s\n", data)
	logrus.WithField("data", data).Info("Data processed")

	pod := createPod(data)
	validatePod(pod)
}

func createPod(name string) *v1.Pod {
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Name:  "main",
					Image: "nginx:latest",
				},
			},
		},
	}
}

func validatePod(pod *v1.Pod) error {
	if pod.Name == "" {
		return fmt.Errorf("pod name cannot be empty")
	}
	return nil
}

func TransformData(input []string) []string {
	result := make([]string, len(input))
	for i, item := range input {
		result[i] = fmt.Sprintf("transformed-%s", item)
	}
	return result
}
