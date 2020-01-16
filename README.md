# PyPsExec C++ Service Library

This is the source code that generates the Windows service binary that is used
in the [pypsexec](https://github.com/jborean93/pypsexec) project.

Originally pypsexec used [PAExec](https://github.com/poweradminllc/PAExec) but
due to a need to add more features and have greater control over the whole
project I've decided to create my own service.

This is current a work in progress and is in no where near ready for use.

## TODO

* Move process creation code into it's own file and define the interface
* Define structures to allow communication between pypsexec and the service
* Setup named pipe communication between the service and pypsexec
* Turn into a Windows service binary
* Tidy up unused API calls that were added in development
* Move the external [wil](https://github.com/Microsoft/wil) library into an actual git submodule instead of a copy
* Probably even more
