#include<cstdlib>
#include<ctime>
#include <fstream>

using namespace std;
int main()
{
	ofstream cout("packet_types.txt");	
	
	srand(time(NULL));
	for (int i=0;i<3;i++)
		cout << rand() << "\n";
}
