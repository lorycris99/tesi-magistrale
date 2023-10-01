#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char* argv[]) {

	if(argc != 2) {
		printf("USAGE:\n");
		printf("%s start/stop\n\n", argv[0]);
		return -1;
	}

	if (!strcmp(argv[1], "start")) {
		printf("Starting vcan0 interface\n");
		//Create virtual CAN interface
		system("sudo ip link add dev vcan0 type vcan");
		//Bring the virtual CAN interface up
		system("sudo ip link set up vcan0");
	} else if(!strcmp(argv[1], "stop")){
		printf("Stopping vcan0 interface\n");
		//Delete virtual CAN interface
		system("sudo ip link del vcan0");
	} else {
		printf("%s: command not found\n\n", argv[1]);
	}
}
