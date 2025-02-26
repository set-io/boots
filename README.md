# bootS

[Chinese](https://github.com/set-io/boots/blob/main/README_zh.md)

> **As lightweight as a container, as secure as a virtual machine**

A Linux server sandbox virtualization CLI tool, spawning and running sandbox according to the `OCI specification`.
boots is inspired by [QEMU][qemu] and [runC][runc], with a focus on being:

* **Simple**: The command line interface of the tool is simple and clear, and users can quickly start, manage and destroy the sandbox environment with simple commands. 
* **Secure**: Each sandbox instance runs in an independent kernel environment, ensuring complete isolation between different sandboxes. This isolation mechanism prevents resource conflicts and potential security vulnerabilities, ensuring the security of each sandbox environment. 
* **Fast**: Lightweight virtualization technology is used to ensure that the sandbox is started and destroyed extremely quickly. Users can start a sandbox environment in seconds and quickly destroy it after completing the task, saving time and resources. 
* **Reliable**: The tool has built-in high availability and fault tolerance mechanisms to ensure that the sandbox environment can be automatically restored or migrated in the event of a failure. Through redundant design and failover strategies, the tool can ensure the continuous availability of the sandbox. 

boots is written in Go and use KVM and virtio as CPU and IO virtualization solutions.

[qemu]: https://github.com/qemu/qemu
[runc]: https://github.com/opencontainers/runc

## Getting Started

### Getting boots

The latest release and setup instructions are available at [GitHub][github-release].

[github-release]: https://github.com/set-io/boots/releases/


### Building

You can build boots from source:

```sh
git clone https://github.com/set-io/boots
cd boots
./make
```

This will generate a binary called `./boots`.

_NOTE_: you need go 1.22+ and Linux 5.0+. Please check your installation with

```
go version
uname -a
```

### Usage

Start the first sandbox virtual environment:

```sh
./boots create --bundle centos7-x86-64-image sandbox01
```

This will create a sandbox, complete the initial resource preparation, and make it ready to run at any time, but it is not running yet. You can trigger it to run at any time.

```sh
./boots start sandbox01
```
The start command is used to start a sandbox in the creation state.

There is a simpler way to combine the create and start phases, as follows:

```
./boots run --bundle centos7-x86-64-image sandbox01
```
If there are no errors, you have successfully created a virtualized sandbox environment.

```
./boots exec sandbox01 "ps -lh /"
```

View the inside of the sandbox or enter the sandbox environment:

```
./boots exec -t sandbox01
```

Stop a running sandbox

```
./boots kill sandbox01
```

## Contact

- Bugs: [issues](https://github.com/set-io/boots/issues)

## Contributing

See [CONTRIBUTING](CONTRIBUTING.md) for details on submitting patches and the contribution workflow.

### License

boots is under the Apache 2.0 license. See the [LICENSE](LICENSE) file for details.
