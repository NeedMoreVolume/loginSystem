// Daniel Pivalizza

//	The goal of this project is to be able to load usernames and passwords from a file, as well as modify the list (change 
// existing details, add new details, delete existing details, and verify details) in a secure and efficient fashion. This will
// be achieved by hashing the passwords and storing the hashes, so when the user enters a password, it comes into the private area
// of the program as to hide which hashing function is being used to be hashed and checked on file for the username entered.
// To further secure the passwords from other attacks, salts (a random string, unique to each user which will be remade for each
// time an entry is changed so that no user's password hash will be the same even if the passwords themselves are the same,
// appended to the password string before hashing) will be utilized.
//	 Since writing one's own hashing algorithm to be secure seems to be discouraged from everything read on the internet, the
// passwords are stored using a SHA2 hash from the OpenSSL library to ensure that it is secure as it has been tested and proven
// to work well, and has no known collisions at the time of writing this code.

#define _CRT_RAND_S

#include <iostream>   
#include <string>  
#include <iomanip>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <sstream>
#include <fstream>
#include <vector>
#include "evp.h" //for sha 256 hash, requires OpenSSl built into windows, the header file I had didn't have everything that was needed as it turned out.
//instructions for installing OpenSSL and linking it properly - http://www.technical-recipes.com/2014/using-openssl-sha-256-in-visual-c/
//I was going to build the OpenSSL into a dll, link it, and drop it in the .zip, but ran out of time. :(

using namespace std;

class user
{
private:
	string username;
	string hashword;
	string salt;
	bool loginFlag;
public:
	user();
	user(string, string, string, bool);
	void displayUser();
	void setPassword(string);
	void setUsername(string);
	void setLoginFlag(bool);
	string getSalt();
	string getHashword();
	string getUsername();
	bool getLoginFlag();
	string sha256(string);
	string makeNewSalt();
};


//Declarations

void showMenu();
bool login(string, string, vector<user> &a);
string ahash(string, string);




void user::displayUser()
{
	cout<<this->username<<" "<<this->hashword<<" "<<this->salt<<endl;
	return;
}


string user::makeNewSalt()
{
	unsigned int number=0;
	char arr [64];
	double max=100;
	int holder=0;
	errno_t         err;
	for (int i = 0; i < 63 ;i++ )
	{
		err = rand_s(&number);
		if (err != 0)
		{
			cout << "The rand_s function failed!" << endl;
		}
		arr[i]=(number%223)+32;
	}
	arr[63]='\0';
	string str(arr);
    return str;
}


string user::sha256(string str)  
{ 
	EVP_MD_CTX *mdctx;
	const EVP_MD *md;
	unsigned char md_value[EVP_MAX_MD_SIZE];
	unsigned int md_len;
	
	md=EVP_sha256();
	mdctx=EVP_MD_CTX_create();
	EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, str.c_str(), str.size());
	EVP_DigestFinal_ex(mdctx, md_value, &md_len);
	EVP_MD_CTX_destroy(mdctx);
	//taken from stackoverflow.com
   stringstream ss;  
    for(unsigned int i = 0; i<md_len; i++)  
    {  
        ss << hex << setw(2) << setfill('0') << (int)md_value[i];  
    }  

    return ss.str();  
}  
//end of taken code.


user::user()
{
	username="", hashword="", salt="", loginFlag=false;
}

user::user(string newUsername, string newHashword, string newSalt, bool newLoginFlag)
{
	username=newUsername;
	hashword=newHashword;
	salt=newSalt;
	loginFlag=newLoginFlag;
}

void user::setPassword(std::string newPassword)
{
	//make a new salt (new salt must always be made when a new password is made) then hash the newPassword+salt, and store that hash.
	salt=makeNewSalt();
	hashword=sha256(newPassword+salt);
	return;
}
void user::setUsername(std::string newUsername)
{
	username=newUsername;
	return;
}
void user::setLoginFlag(bool newFlag)
{
	loginFlag=newFlag;
	return;
}
std::string user::getSalt()
{
	return salt;
}
std::string user::getHashword()
{
	return hashword;
}
std::string user::getUsername()
{
	return username;
}
bool user::getLoginFlag()
{
	return loginFlag;
}


string ahash(string password, string salt)
{
	EVP_MD_CTX *mdctx;
	const EVP_MD *md;
	unsigned char md_value[EVP_MAX_MD_SIZE];
	unsigned int md_len;
	string str=password+salt;
	
	md=EVP_sha256();
	mdctx=EVP_MD_CTX_create();
	EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, str.c_str(), str.size());
	EVP_DigestFinal_ex(mdctx, md_value, &md_len);
	EVP_MD_CTX_destroy(mdctx);
	//taken from stackoverflow.com
   stringstream ss;  
    for(unsigned int i = 0; i<md_len; i++)  
    {  
        ss << hex << setw(2) << setfill('0') << (int)md_value[i];  
    }  

    return ss.str();
}

bool login(string username, string password, vector<user> &a)
{
	string aSalt="", passwordHash="";
	//search vector for username
	for(unsigned int i=0; i<a.size(); i++)
	{
		if(a[i].getUsername()==username)//if found, set that user in the vector to user loggingIn.
		{
			passwordHash=ahash(password, a[i].getSalt());
			a[i].setLoginFlag(a[i].getHashword()==passwordHash);//if the hashes match, set the login flag to true;
			return a[i].getLoginFlag();
		}
	}
	return false;//else if the passwords for that user don't match, login fails.

}
	

void showMenu()
{
	cout << "1. Login." << endl << "2. Make new user." << endl << "3. Quit." << endl;
	cout << "4.  Modiy an account password." << endl << "5. Uhh... Maybe we'll think of something else to do." << endl << "6. Delete an account." << endl << "7. Logout." << endl;
}

int main()
{
	cout << "Welcome to the CS2410 project menu by Daniel Pivalizza. Let's get started..." << endl;
	vector<user> userList=vector<user>();
	string aUsername="", aHashword="", aSalt="", password="", newPassword="";
	bool loginFlag= false;
	unsigned int count=0, i=0;
	char choice=' ';
	string retry;
	ifstream inFile;
	user aUser;
	inFile.open("userdata.dat");
	while(inFile)//if inFile has something, get it.
	{
		getline(inFile, aUsername);
		getline(inFile, aHashword);
		getline(inFile, aSalt);
		if(aUsername!="")//just to make sure new line elements for user credentials don't get put into the userList.
		{
			userList.push_back(user(aUsername, aHashword, aSalt, false));
			i++;//increment user count.
		}
	}
	inFile.close();
	ofstream outFile;
	cout << "Okay, we're all ready, please enter the number of an option from the  below." << endl;
	while(choice!='3')
	{
		showMenu();
		cin >> choice;
		cout << "Just to confirm, you chose " << choice << ". If this is not correct, please enter \"no\", else hit any button and enter to continue." << endl;
		cin>>retry;
		if(retry=="no")
		{
			choice=0;
			cout << "Okay, let me show you the  again." << endl;
			break;
		}
		user newUser;
		switch(choice)
		{
		case '0':
			break;
		case '1':
			cout << "Please enter your username and password." << endl;
			cin >> aUsername; 
			cin >> password;
			if(login(aUsername, password, *&userList))
			{
				cout << "Login successful." << endl;
			}
			else
			{
				cout << "Login failed." << endl;
			}
			break;
		case '2':
			cout << "Please enter a username and password." << endl;
			cin >> aUsername;
			cin >> password;
			//check if username is already taken.
			for(count=0; count<userList.size(); count++)
			{
				while(userList[count].getUsername()==aUsername)//as long as the username is taken
				{
					cout << "Sorry, that username is already taken, please pick another one." << endl;
					cin >> aUsername;
					count=0;//restart username check from beginning of the vector.
				}
			}
			newUser.setUsername(aUsername);//store info in a user data type
			newUser.setPassword(password);
			newUser.setLoginFlag(false);
			userList.push_back(newUser);//make a new user at the end of the set from user data type
			i++;//increment user count.
			break;
		case '3':
			cout << "Okay, closing the program and saving any open files. Please do not turn off the machine until the program has terminated." << endl;
			outFile.open("userdata.dat", ios::out, ios::trunc);
			for(count=0; count<i;count++)//for every entry, copy the userdata into the outFile.
			{
				outFile << userList[count].getUsername() << "\n" << userList[count].getHashword() << "\n" << userList[count].getSalt();
				if(count!=i)
				{
					outFile << "\n";
				}
			}
			cout << "Save successful." << endl;
			outFile.close();
			break;
		case '4':
			cout << "Okay, fair enough, you might need to change a password every once in awhile, or every 90 days." << endl;
			cout << "Please enter your username current password and then the new password you desire." << endl;
			cin >> aUsername;
			cin >> password;
			cin >> newPassword;
			//go through the vector and check username and password.
			for( std::vector<user>::iterator iter = userList.begin(); iter != userList.end(); ++iter )
			{
				aUser=*iter;//set the iterator to load the user in the iterator's position of the vector into a user data type, so we can check the elements that live in the user.
				if( aUser.getUsername() == aUsername )//if username matches, check the password for that user
				{
					if(aUser.getHashword()==ahash(password, aUser.getSalt()))//if the password also matches, try to set a new password.
					{
						aUser.setPassword(newPassword);
						//set aUser to the iterator position maybe?
						*iter=aUser;
						break;//break out of here when aUser is loaded into the iterator's position in the vector.
					}
			    }
			}
			//check to see that the password and username match for each other, we don't want people changing other people's login credentials.
			break;
		case '5':
			cout << "Haha, since this is for fun, let's see who's logged in." << endl;
			count=0;
			for(count; count<userList.size();count++)
			{
				if(userList[count].getLoginFlag())
				{
					cout << userList[count].getUsername() << " is logged in." << endl;
				}
			}
			break;
		case '6': 
			cout << "Please enter the username of the user to delete." << endl;
			cin >> aUsername;
			//search the vector for a username
			for( std::vector<user>::iterator iter = userList.begin(); iter != userList.end(); ++iter )
			{
				aUser=*iter;//set the iterator to load the user into a user data type, so we can check the elements that live in the user.
				if( aUser.getUsername() == aUsername )//if username matches, remove the user element at that position.
				{
					userList.erase(iter);
					break;
			    }
			}
			break;
		case '7':
			cout << "Okay, all users are automatically logged out upon exit, but we can log a specific account out if you would like." << endl;
			cout << "Please enter your username and your password, if logged out, nothing will happen." << endl;//since this emulates a server side implementation of a login system, as such the client would always send this with requests
			cin >> aUsername;
			cin >> password;
			count=0;
			for(count; count<userList.size();count++)
			{
				if(userList[count].getUsername()==aUsername)//if username exists
				{
					if(userList[count].getHashword()==ahash(password, userList[count].getSalt()))//check hashes and set loginflag
					{
						userList[count].setLoginFlag(false);
						cout << "The deed is done, your account is now logged out." << endl;
					}
					else
					{
						cout << "Oops, wrong credentials entered. You lose this round, user." << endl;
					}
				}
			}
			break;
		default:
			cout << "Hmm, your entry doesn't seem to match anything on the menu. Please try again." << endl;
			break;
		};
		count++;
	}
	system("PAUSE");
	return 0;
}