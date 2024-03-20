#include <iostream>
#include <getopt.h>
using namespace std;

void help(int32_t ext){
  cout << "help" << endl;
}

int main(int argc, char* argv[]) {
  if (argc > 1 && strncmp(argv[1], "-h", 2) == 0) help(1);
  if (argc < 2) help(0);

}