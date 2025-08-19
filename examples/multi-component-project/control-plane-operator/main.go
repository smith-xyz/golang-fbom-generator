package main

import (
	"fmt"

	"github.com/example/multi-component-project/pkg/processor"
	"github.com/example/multi-component-project/support"
)

func main() {
	fmt.Println("Control plane operator entry point")
	runControlPlaneOperator()
}

func runControlPlaneOperator() {
	fmt.Println("Running control plane operator")
	processor.ProcessData("control-plane-data")
	support.InitializeSupport()
	reconcileControlPlane()
}

func reconcileControlPlane() {
	fmt.Println("Reconciling control plane")
	manageKubeAPIServer()
	manageEtcd()
}

func manageKubeAPIServer() {
	fmt.Println("Managing kube-apiserver")
}

func manageEtcd() {
	fmt.Println("Managing etcd")
}
