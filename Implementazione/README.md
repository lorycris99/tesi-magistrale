# Implementation
In this folder is placed all the source code necessary to run the application made. Some warnings before proceeding:
1. The code can run only under Linux (tested on Ubuntu 22.04), i don't know if it will work under **WSL**;
2. Before executing the application, compilation of the libraries is needed. Check the docs of CAN-utils and pqcrystals-kyber to know how to compile everything. For kyber, **shared objects** are needed so check the correct section in the docs (for CAN-utils just the executables);
3. There is a file named `guida.txt` in the folder `tester` with some commands to execute before to correctly compile the code.
4. To start the CAN virtual device, you must:
   1. Execute the command `sudo modprobe vcan`;
   2. Compile the `can.c` file found in the root;
   3. Execute the compiled file with argument `start`;

To execute the main application, you can compile the test file found inside `tester` folder and the `sender` folder contains another application made to execute the testing phase.