#include <iostream>
#include <cstring>
#include <ctime>
#include <fstream>  // ADDED for file handling
using namespace std;

struct User {
    char username[50];
    char password[50];
    char role[20];
    int accessLevel;
    bool isActive;
};
struct FailedLoginNode {
    char username[50];
    int attemptNumber;
    FailedLoginNode* next;
};
struct SessionNode {
    char username[50];
    SessionNode* prev;
    SessionNode* next;
};
struct CircularUserNode {
    char username[50];
    CircularUserNode* next;
};
struct PasswordNode {
    char password[50];
    PasswordNode* next;
};
struct SuspiciousActivityNode {
    char username[50];
    int failedAttempts;
    char timestamp[20];
    SuspiciousActivityNode* next;
};
struct ThreatNode {
    char username[50];
    char threatType[100];
    int priority;
    char timestamp[20];
    ThreatNode* next;
};
struct BSTNode {
    char username[50];
    int accessLevel;
    char role[20];
    BSTNode* left;
    BSTNode* right;
};
User* users = NULL;
int userCount = 0;
int userCapacity = 20;
FailedLoginNode* failedLoginHead = NULL;
SessionNode* sessionHead = NULL;
SessionNode* sessionTail = NULL;
CircularUserNode* circularHead = NULL;
CircularUserNode* circularTail = NULL;
SuspiciousActivityNode* suspiciousQueueFront = NULL;
SuspiciousActivityNode* suspiciousQueueRear = NULL;
ThreatNode* threatQueueHead = NULL;
BSTNode* accessTreeRoot = NULL;
struct UserPasswordHistory {
    char username[50];
    PasswordNode* passwordStack;
};
UserPasswordHistory passwordHistory[50];
int passwordHistoryCount = 0;
char currentLoggedInUser[50] = "";

void pause() {
    cout << "\nPress Enter to continue";
    cin.ignore();
    cin.get();
}

void countdownTimer(int seconds) {
    cout << "\n[SECURITY] Please wait for " << seconds << " seconds before trying again..." << endl;

    time_t startTime = time(0);
    time_t currentTime;
    int elapsed = 0;

    while (elapsed < seconds) {
        currentTime = time(0);
        elapsed = difftime(currentTime, startTime);
        int remaining = seconds - elapsed;

        if (remaining >= 0) {
            cout << "\rTime remaining: " << remaining << " seconds  " << flush;
        }

        for (volatile long i = 0; i < 100000000; i++);
    }

    cout << "\n[INFO] You can now try again.                    " << endl;
}

void addToBST(char* username, char* role, int accessLevel) {
    BSTNode* node = new BSTNode;
    strcpy(node->username, username);
    strcpy(node->role, role);
    node->accessLevel = accessLevel;
    node->left = node->right = NULL;

    if (accessTreeRoot == NULL) {
        accessTreeRoot = node;
    } else {
        BSTNode* temp = accessTreeRoot;
        BSTNode* parent = NULL;
        while (temp != NULL) {
            parent = temp;
            if (node->accessLevel < temp->accessLevel)
                temp = temp->left;
            else
                temp = temp->right;
        }
        if (node->accessLevel < parent->accessLevel)
            parent->left = node;
        else
            parent->right = node;
    }
}

void initializeDynamicArray() {
    users = new User[userCapacity];
    userCount = 0;

    ifstream inputFile("users-3.txt");
    
    if (!inputFile.is_open()) {
        cout << "\n[ERROR] Could not open 'users-3.txt' file!" << endl;
        cout << "[INFO] Make sure the file exists in the same directory as the program." << endl;
        return;
    }

    cout << "\n[INFO] Loading users from file 'users-3.txt'..." << endl;

    while (!inputFile.eof() && userCount < userCapacity) {
        inputFile >> users[userCount].username 
                  >> users[userCount].password 
                  >> users[userCount].role 
                  >> users[userCount].accessLevel;

        if (inputFile.fail()) {
            break;
        }

        users[userCount].isActive = false;

        addToBST(users[userCount].username, 
                 users[userCount].role, 
                 users[userCount].accessLevel);

        cout << "[+] Loaded: " << users[userCount].username 
             << " (Role: " << users[userCount].role 
             << ", Access Level: " << users[userCount].accessLevel << ")" << endl;

        userCount++;

        if (userCount >= userCapacity - 1) {
            int newCapacity = userCapacity * 2;
            User* newUsers = new User[newCapacity];

            for (int i = 0; i < userCount; i++) {
                newUsers[i] = users[i];
            }

            delete[] users;
            users = newUsers;
            userCapacity = newCapacity;
            
            cout << "[INFO] Array resized to capacity: " << userCapacity << endl;
        }
    }

    inputFile.close();

    cout << "\n[SUCCESS] " << userCount << " users loaded successfully from file!" << endl;
    cout << "[INFO] Current capacity: " << userCapacity << endl;
}

void resizeDynamicArray() {
    int newCapacity = userCapacity * 2;
    User* newUsers = new User[newCapacity];

    for (int i = 0; i < userCount; i++) {
        newUsers[i] = users[i];
    }

    delete[] users;
    users = newUsers;
    userCapacity = newCapacity;

    cout << " Dynamic array resized! New capacity: " << userCapacity << endl;
}

void registerUser() {
    if (userCount >= userCapacity) {
        resizeDynamicArray();
    }
    cout << "\n     USER REGISTRATION     " << endl;
    cout << "Enter Username: ";
    cin >> users[userCount].username;
    for (int i = 0; i < userCount; i++) {
        if (strcmp(users[i].username, users[userCount].username) == 0) {
            cout << " Username already exists!" << endl;
            return;
        }
    }

    cout << "Enter Password: ";
    cin >> users[userCount].password;

    cout << "\nSelect Role:" << endl;
    cout << "1. Guest " << endl;
    cout << "2. User " << endl;
    cout << "3. Admin " << endl;
    cout << "Choice: ";
    int roleChoice;
    cin >> roleChoice;

    switch(roleChoice) {
        case 1:
            strcpy(users[userCount].role, "Guest");
            users[userCount].accessLevel = 1;
            break;
        case 2:
            strcpy(users[userCount].role, "User");
            users[userCount].accessLevel = 2;
            break;
        case 3:
            strcpy(users[userCount].role, "Admin");
            users[userCount].accessLevel = 3;
            break;
        default:
            strcpy(users[userCount].role, "User");
            users[userCount].accessLevel = 2;
    }

    users[userCount].isActive = false;
    
    addToBST(users[userCount].username, users[userCount].role, users[userCount].accessLevel);

    cout << "\n User '" << users[userCount].username << "' registered as "
         << users[userCount].role << "!" << endl;
    cout << " Current users: " << (userCount + 1) << "/" << userCapacity << endl;
    userCount++;
}

int linearSearch(char* username, char* password) {
    for (int i = 0; i < userCount; i++) {
        if (strcmp(users[i].username, username) == 0 &&
            strcmp(users[i].password, password) == 0) {
            return i;
        }
    }
    return -1;
}

void sortUsersForBinarySearch(User* sortedUsers) {
    for (int i = 0; i < userCount; i++) {
        sortedUsers[i] = users[i];
    }

    for (int i = 0; i < userCount - 1; i++) {
        for (int j = 0; j < userCount - i - 1; j++) {
            if (strcmp(sortedUsers[j].username, sortedUsers[j + 1].username) > 0) {
                User temp = sortedUsers[j];
                sortedUsers[j] = sortedUsers[j + 1];
                sortedUsers[j + 1] = temp;
            }
        }
    }
}

int binarySearch(char* username, char* password) {
    User* sortedUsers = new User[userCount];
    sortUsersForBinarySearch(sortedUsers);

    int left = 0, right = userCount - 1;
    int foundIndex = -1;

    while (left <= right) {
        int mid = left + (right - left) / 2;
        int cmp = strcmp(sortedUsers[mid].username, username);

        if (cmp == 0) {
            if (strcmp(sortedUsers[mid].password, password) == 0) {
                for (int i = 0; i < userCount; i++) {
                    if (strcmp(users[i].username, username) == 0) {
                        foundIndex = i;
                        break;
                    }
                }
                break;
            } else {
                foundIndex = -1;
                break;
            }
        }

        if (cmp < 0) {
            left = mid + 1;
        } else {
            right = mid - 1;
        }
    }

    delete[] sortedUsers;
    return foundIndex;
}

void addFailedLogin(char* username) {
    int attempts = 0;
    FailedLoginNode* temp = failedLoginHead;
    while (temp != NULL) {
        if (strcmp(temp->username, username) == 0) {
            attempts++;
        }
        temp = temp->next;
    }
    attempts++;

    FailedLoginNode* newNode = new FailedLoginNode;
    strcpy(newNode->username, username);
    newNode->attemptNumber = attempts;
    newNode->next = failedLoginHead;
    failedLoginHead = newNode;

    cout << "[WARNING] Failed login attempt #" << attempts << " for user: " << username << endl;

    bool isAdmin = false;
    for (int i = 0; i < userCount; i++) {
        if (strcmp(users[i].username, username) == 0 && users[i].accessLevel == 3) {
            isAdmin = true;
            break;
        }
    }

    if (attempts >= 3 || (isAdmin && attempts >= 1)) {
        cout << " User '" << username << "' marked as SUSPICIOUS!" << endl;

        bool alreadyInQueue = false;
        SuspiciousActivityNode* checkNode = suspiciousQueueFront;
        while (checkNode != NULL) {
            if (strcmp(checkNode->username, username) == 0) {
                alreadyInQueue = true;
                checkNode->failedAttempts = attempts;
                break;
            }
            checkNode = checkNode->next;
        }

        if (!alreadyInQueue) {
            SuspiciousActivityNode* susNode = new SuspiciousActivityNode;
            strcpy(susNode->username, username);
            susNode->failedAttempts = attempts;
            susNode->next = NULL;

            if (suspiciousQueueFront == NULL) {
                suspiciousQueueFront = suspiciousQueueRear = susNode;
            } else {
                suspiciousQueueRear->next = susNode;
                suspiciousQueueRear = susNode;
            }
        }

        ThreatNode* threatNode = new ThreatNode;
        strcpy(threatNode->username, username);

        if (attempts >= 3 || isAdmin) {
            threatNode->priority = 3;
            if (isAdmin) {
                strcpy(threatNode->threatType, "Admin Account Attack");
            } else {
                strcpy(threatNode->threatType, "Multiple Failed Login Attempts");
            }
        } else if (attempts == 2) {
            threatNode->priority = 2;
            strcpy(threatNode->threatType, "Suspicious Login Activity");
        } else {
            threatNode->priority = 1;
            strcpy(threatNode->threatType, "First Failed Login");
        }

        threatNode->next = NULL;

        if (threatQueueHead == NULL || threatQueueHead->priority < threatNode->priority) {
            threatNode->next = threatQueueHead;
            threatQueueHead = threatNode;
        } else {
            ThreatNode* temp = threatQueueHead;
            while (temp->next != NULL && temp->next->priority >= threatNode->priority) {
                temp = temp->next;
            }
            threatNode->next = temp->next;
            temp->next = threatNode;
        }
    }

    countdownTimer(10);
}

void viewFailedLoginAttempts() {
    cout << "\n     FAILED LOGIN ATTEMPTS     " << endl;

    if (failedLoginHead == NULL) {
        cout << "No failed login attempts recorded." << endl;
        return;
    }

    cout << "\nUsername\t\tAttempt #" << endl;
    cout << "----------------------------------------" << endl;
    FailedLoginNode* temp = failedLoginHead;
    while (temp != NULL) {
        cout << temp->username << "\t\t\t" << temp->attemptNumber << endl;
        temp = temp->next;
    }
}

void addActiveSession(char* username) {
    SessionNode* newNode = new SessionNode;
    strcpy(newNode->username, username);
    newNode->prev = NULL;
    newNode->next = NULL;

    if (sessionHead == NULL) {
        sessionHead = sessionTail = newNode;
    } else {
        sessionTail->next = newNode;
        newNode->prev = sessionTail;
        sessionTail = newNode;
    }

    CircularUserNode* circNode = new CircularUserNode;
    strcpy(circNode->username, username);

    if (circularHead == NULL) {
        circularHead = circularTail = circNode;
        circNode->next = circularHead;
    } else {
        circNode->next = circularHead;
        circularTail->next = circNode;
        circularTail = circNode;
    }
}

void removeActiveSession(char* username) {
    SessionNode* temp = sessionHead;

    while (temp != NULL) {
        if (strcmp(temp->username, username) == 0) {
            if (temp == sessionHead && temp == sessionTail) {
                sessionHead = sessionTail = NULL;
            } else if (temp == sessionHead) {
                sessionHead = temp->next;
                sessionHead->prev = NULL;
            } else if (temp == sessionTail) {
                sessionTail = temp->prev;
                sessionTail->next = NULL;
            } else {
                temp->prev->next = temp->next;
                temp->next->prev = temp->prev;
            }
            delete temp;
            break;
        }
        temp = temp->next;
    }

    if (circularHead != NULL) {
        CircularUserNode* curr = circularHead;
        CircularUserNode* prev = circularTail;

        do {
            if (strcmp(curr->username, username) == 0) {
                if (curr == circularHead && curr == circularTail) {
                    delete curr;
                    circularHead = circularTail = NULL;
                } else if (curr == circularHead) {
                    circularHead = curr->next;
                    circularTail->next = circularHead;
                    delete curr;
                } else if (curr == circularTail) {
                    circularTail = prev;
                    circularTail->next = circularHead;
                    delete curr;
                } else {
                    prev->next = curr->next;
                    delete curr;
                }
                break;
            }
            prev = curr;
            curr = curr->next;
        } while (curr != circularHead && circularHead != NULL);
    }
}

void viewActiveSessions() {
    cout << "\n     ACTIVE USER SESSIONS     " << endl;

    if (sessionHead == NULL) {
        cout << "No active sessions." << endl;
        return;
    }

    cout << "\nForward Traversal (Head to Tail):" << endl;
    SessionNode* temp = sessionHead;
    while (temp != NULL) {
        cout << temp->username;
        if (temp->next != NULL) cout << "  ";
        temp = temp->next;
    }
    cout << endl;

    cout << "\nBackward Traversal (Tail to Head):" << endl;
    temp = sessionTail;
    while (temp != NULL) {
        cout << temp->username;
        if (temp->prev != NULL) cout << "  ";
        temp = temp->prev;
    }
    cout << endl;
}

void displayActiveUsersRotation() {
    cout << "\n     ACTIVE USERS ROTATION (Round-Robin)     " << endl;

    if (circularHead == NULL) {
        cout << "No active users." << endl;
        return;
    }

    cout << "\nDisplaying 10 rotations of active users:" << endl;
    CircularUserNode* temp = circularHead;
    for (int i = 0; i < 10; i++) {
        cout << temp->username << " -> ";
        temp = temp->next;
    }
    cout << "(continues...)" << endl;
}

void pushPasswordHistory(char* username, char* password) {
    int userIndex = -1;
    for (int i = 0; i < passwordHistoryCount; i++) {
        if (strcmp(passwordHistory[i].username, username) == 0) {
            userIndex = i;
            break;
        }
    }

    if (userIndex == -1) {
        strcpy(passwordHistory[passwordHistoryCount].username, username);
        passwordHistory[passwordHistoryCount].passwordStack = NULL;
        userIndex = passwordHistoryCount;
        passwordHistoryCount++;
    }

    PasswordNode* newNode = new PasswordNode;
    strcpy(newNode->password, password);
    newNode->next = passwordHistory[userIndex].passwordStack;
    passwordHistory[userIndex].passwordStack = newNode;
}

void changePassword() {
    if (sessionHead == NULL) {
        cout << "\n[ERROR] No users are currently logged in! Please login first." << endl;
        return;
    }

    cout << "\n========== CHANGE PASSWORD ==========" << endl;

    cout << "\nCurrently logged in users:" << endl;
    SessionNode* temp = sessionHead;
    int count = 1;
    while (temp != NULL) {
        cout << count++ << ". " << temp->username << endl;
        temp = temp->next;
    }

    cout << "\nEnter username to change password: ";
    char username[50];
    cin >> username;

    bool isLoggedIn = false;
    temp = sessionHead;
    while (temp != NULL) {
        if (strcmp(temp->username, username) == 0) {
            isLoggedIn = true;
            break;
        }
        temp = temp->next;
    }

    if (!isLoggedIn) {
        cout << "[ERROR] User '" << username << "' is not currently logged in!" << endl;
        return;
    }

    char oldPassword[50], newPassword[50];
    cout << "Enter current password: ";
    cin >> oldPassword;

    int userIndex = -1;
    for (int i = 0; i < userCount; i++) {
        if (strcmp(users[i].username, username) == 0) {
            if (strcmp(users[i].password, oldPassword) == 0) {
                userIndex = i;
                break;
            }
        }
    }

    if (userIndex == -1) {
        cout << " Incorrect current password!" << endl;
        return;
    }

    cout << "Enter new password: ";
    cin >> newPassword;

    int histIndex = -1;
    for (int i = 0; i < passwordHistoryCount; i++) {
        if (strcmp(passwordHistory[i].username, username) == 0) {
            histIndex = i;
            break;
        }
    }

    if (histIndex != -1 && passwordHistory[histIndex].passwordStack != NULL) {
        if (strcmp(passwordHistory[histIndex].passwordStack->password, newPassword) == 0) {
            cout << "[ERROR] Cannot reuse the last password!" << endl;
            return;
        }
    }

    pushPasswordHistory(username, users[userIndex].password);

    strcpy(users[userIndex].password, newPassword);

    cout << " Password changed successfully for user '" << username << "'!" << endl;

    ThreatNode* threatNode = new ThreatNode;
    strcpy(threatNode->username, username);
    strcpy(threatNode->threatType, "Password Changed");
    threatNode->priority = 2;
    threatNode->next = NULL;

    if (threatQueueHead == NULL || threatQueueHead->priority < threatNode->priority) {
        threatNode->next = threatQueueHead;
        threatQueueHead = threatNode;
    } else {
        ThreatNode* temp = threatQueueHead;
        while (temp->next != NULL && temp->next->priority >= threatNode->priority) {
            temp = temp->next;
        }
        threatNode->next = temp->next;
        temp->next = threatNode;
    }
}

void viewPasswordHistory() {
    if (sessionHead == NULL) {
        cout << "\n No users are currently logged in! Please login first." << endl;
        return;
    }

    cout << "\n     PASSWORD HISTORY     " << endl;

    cout << "\nCurrently logged in users:" << endl;
    SessionNode* temp = sessionHead;
    int count = 1;
    while (temp != NULL) {
        cout << count++ << ". " << temp->username << endl;
        temp = temp->next;
    }

    cout << "\nEnter username to view password history: ";
    char username[50];
    cin >> username;

    bool isLoggedIn = false;
    temp = sessionHead;
    while (temp != NULL) {
        if (strcmp(temp->username, username) == 0) {
            isLoggedIn = true;
            break;
        }
        temp = temp->next;
    }

    if (!isLoggedIn) {
        cout << "[ERROR] User '" << username << "' is not currently logged in!" << endl;
        return;
    }

    int histIndex = -1;
    for (int i = 0; i < passwordHistoryCount; i++) {
        if (strcmp(passwordHistory[i].username, username) == 0) {
            histIndex = i;
            break;
        }
    }

    if (histIndex == -1 || passwordHistory[histIndex].passwordStack == NULL) {
        cout << "No password history available for user '" << username << "'." << endl;
        return;
    }

    cout << "\nLast 3 passwords for user '" << username << "':" << endl;
    PasswordNode* passTemp = passwordHistory[histIndex].passwordStack;
    int passCount = 0;
    while (passTemp != NULL && passCount < 3) {
        cout << (passCount + 1) << ". " << passTemp->password << endl;
        passTemp = passTemp->next;
        passCount++;
    }
}

void viewSuspiciousActivityLogs() {
    cout << "\n     SUSPICIOUS ACTIVITY LOGS (FIFO)     " << endl;

    if (suspiciousQueueFront == NULL) {
        cout << "No suspicious activities recorded." << endl;
        return;
    }

    cout << "\n#\tUsername\t\tFailed Attempts\tTimestamp" << endl;
    SuspiciousActivityNode* temp = suspiciousQueueFront;
    int count = 1;
    while (temp != NULL) {
        cout << count++ << "\t" << temp->username << "\t\t\t" << temp->failedAttempts << endl;
        temp = temp->next;
    }
}

void viewThreatPriorityQueue() {
    cout << "\n     THREAT PRIORITY QUEUE     " << endl;

    if (threatQueueHead == NULL) {
        cout << "No threats detected." << endl;
        return;
    }

    cout << "\n#\tUsername\t\tThreat Type\t\t\t\tPriority\tTimestamp" << endl;

    ThreatNode* temp = threatQueueHead;
    int count = 1;
    while (temp != NULL) {
        cout << count++ << "\t" << temp->username << "\t\t";

        cout << temp->threatType;
        int len = strlen(temp->threatType);
        for (int i = len; i < 32; i++) cout << " ";

        cout << "\t";

        switch(temp->priority) {
            case 3:
                cout << "HIGH (3)";
                break;
            case 2:
                cout << "MEDIUM (2)";
                break;
            case 1:
                cout << "LOW (1)";
                break;
        }

        temp = temp->next;
    }
}

void handleTopThreat() {
    if (threatQueueHead == NULL) {
        cout << "\n No threats to handle." << endl;
        return;
    }

    cout << "\n     HANDLING TOP PRIORITY THREAT     " << endl;
    cout << "Username: " << threatQueueHead->username << endl;
    cout << "Threat Type: " << threatQueueHead->threatType << endl;
    cout << "Priority: ";

    switch(threatQueueHead->priority) {
        case 3:
            cout << "HIGH (3)";
            break;
        case 2:
            cout << "MEDIUM (2)";
            break;
        case 1:
            cout << "LOW (1)";
            break;
    }
    cout << endl;

    cout << "\n Threat has been handled and removed from queue." << endl;

    ThreatNode* temp = threatQueueHead;
    threatQueueHead = threatQueueHead->next;
    delete temp;
}

void bubbleSortThreatsByPriority() {
    if (threatQueueHead == NULL || threatQueueHead->next == NULL) {
        cout << "\n Not enough threats to sort." << endl;
        return;
    }

    int count = 0;
    ThreatNode* temp = threatQueueHead;
    while (temp != NULL) {
        count++;
        temp = temp->next;
    }

    struct ThreatData {
        char username[50];
        char threatType[100];
        int priority;
        char timestamp[20];
    };

    ThreatData* threats = new ThreatData[count];
    temp = threatQueueHead;
    for (int i = 0; i < count; i++) {
        strcpy(threats[i].username, temp->username);
        strcpy(threats[i].threatType, temp->threatType);
        threats[i].priority = temp->priority;
        strcpy(threats[i].timestamp, temp->timestamp);
        temp = temp->next;
    }

    for (int i = 0; i < count - 1; i++) {
        for (int j = 0; j < count - i - 1; j++) {
            if (threats[j].priority < threats[j + 1].priority) {
                ThreatData tempData = threats[j];
                threats[j] = threats[j + 1];
                threats[j + 1] = tempData;
            }
        }
    }

    cout << "\n     SORTED THREATS by level     " << endl;
    cout << "\n#\tUsername\t\tThreat Type\t\t\t\tPriority" << endl;
    cout << "-------------------------------------------------------------------------------------" << endl;

    for (int i = 0; i < count; i++) {
        cout << (i + 1) << "\t" << threats[i].username << "\t\t";
        cout << threats[i].threatType;
        int len = strlen(threats[i].threatType);
        for (int j = len; j < 32; j++) cout << " ";
        cout << "\t" << threats[i].priority << "\t\t" << threats[i].timestamp << endl;
    }

    delete[] threats;
}

void selectionSortThreatsByTime() {
    if (threatQueueHead == NULL || threatQueueHead->next == NULL) {
        cout << "\n Not enough threats to sort." << endl;
        return;
    }

    int count = 0;
    ThreatNode* temp = threatQueueHead;
    while (temp != NULL) {
        count++;
        temp = temp->next;
    }

    struct ThreatData {
        char username[50];
        char threatType[100];
        int priority;
        char timestamp[20];
    };

    ThreatData* threats = new ThreatData[count];
    temp = threatQueueHead;
    for (int i = 0; i < count; i++) {
        strcpy(threats[i].username, temp->username);
        strcpy(threats[i].threatType, temp->threatType);
        threats[i].priority = temp->priority;
        strcpy(threats[i].timestamp, temp->timestamp);
        temp = temp->next;
    }

    for (int i = 0; i < count - 1; i++) {
        int minIdx = i;
        for (int j = i + 1; j < count; j++) {
            if (strcmp(threats[j].timestamp, threats[minIdx].timestamp) < 0) {
                minIdx = j;
            }
        }
        if (minIdx != i) {
            ThreatData tempData = threats[i];
            threats[i] = threats[minIdx];
            threats[minIdx] = tempData;
        }
    }

    cout << "\n      SORTED THREATS by time      " << endl;
    cout << "\n#\tUsername\t\tThreat Type\t\t\t\tPriority\tTimestamp" << endl;
    cout << "-------------------------------------------------------------------------------------" << endl;

    for (int i = 0; i < count; i++) {
        cout << (i + 1) << "\t" << threats[i].username << "\t\t";
        cout << threats[i].threatType;
        int len = strlen(threats[i].threatType);
        for (int j = len; j < 32; j++) cout << " ";
        cout << "\t" << threats[i].priority << "\t\t" << threats[i].timestamp << endl;
    }

    delete[] threats;
}

void sortLogsMenu() {
    cout << "\n========== SORT LOGS ==========" << endl;
    cout << "1. Sort Threats by Priority (Bubble Sort - Descending)" << endl;
    cout << "2. Sort Threats by Time (Selection Sort - Ascending)" << endl;
    cout << "3. Back to Main Menu" << endl;
    cout << "\nEnter your choice: ";

    int choice;
    cin >> choice;

    switch(choice) {
        case 1:
            bubbleSortThreatsByPriority();
            break;
       case 2:
            selectionSortThreatsByTime();
            break;
        case 3:
            return;
        default:
            cout << " Invalid choice!" << endl;
    }
}

// ==================== BST (User Access Control) ====================

void inorderTraversal(BSTNode* node) {
    if (node == NULL) return;

    inorderTraversal(node->left);
    cout << "Username: " << node->username
         << "  Access Level: " << node->accessLevel
         << "  Role: " << node->role << endl;
    inorderTraversal(node->right);
}

void displayUserAccessTree() {
    cout << "\n      USER ACCESS HIERARCHY (BST - Inorder)      " << endl;

    if (accessTreeRoot == NULL) {
        cout << "No users in access tree." << endl;
        return;
    }

    cout << "\nAccess Level Hierarchy:" << endl;
    cout << "Level 1 = Guest | Level 2 = User | Level 3 = Admin" << endl;
    inorderTraversal(accessTreeRoot);
}

// ==================== LOGIN FUNCTION ====================

void loginUser() {
    cout << "\n      USER LOGIN      " << endl;

    char username[50], password[50];
    cout << "Enter Username: ";
    cin >> username;
    cout << "Enter Password: ";
    cin >> password;

    cout << "\nSelect Search Method:" << endl;
    cout << "1. Linear Search (Unsorted)" << endl;
    cout << "2. Binary Search (Sorted)" << endl;
    cout << "Choice: ";
    int choice;
    cin >> choice;

    int userIndex = -1;

    if (choice == 1) {
        cout << "\n Using Linear Search" << endl;
        userIndex = linearSearch(username, password);
    } else if (choice == 2) {
        cout << "\n Using Binary Search" << endl;
        userIndex = binarySearch(username, password);
    } else {
        cout << " Invalid choice!" << endl;
        return;
    }

    if (userIndex == -1) {
        cout << "[ERROR] Invalid username or password!" << endl;
        addFailedLogin(username);
        return;
    }

    // Check if THIS specific user is already logged in
    if (users[userIndex].isActive) {
        cout << " User '" << username << "' is already logged in!" << endl;
        cout << "You cannot login twice with the same account." << endl;
        return;
    }

    // Successful login - multiple users can be logged in at the same time
    users[userIndex].isActive = true;
    addActiveSession(username);

    // Update current logged in user to the latest one
    strcpy(currentLoggedInUser, username);

    cout << "\n Login successful!" << endl;
    cout << "Welcome, " << username << " (" << users[userIndex].role << ")" << endl;
}

void logoutUser() {
    if (sessionHead == NULL) {
        cout << "\n[ERROR] No users are currently logged in!" << endl;
        return;
    }

    cout << "\n      USER LOGOUT      " << endl;

    // Show currently logged in users
    cout << "\nCurrently logged in users:" << endl;
    SessionNode* temp = sessionHead;
    int count = 1;
    while (temp != NULL) {
        cout << count++ << ". " << temp->username << endl;
        temp = temp->next;
    }

    cout << "\nEnter username to logout: ";
    char usernameToLogout[50];
    cin >> usernameToLogout;

    // Check if this user is actually logged in
    bool found = false;
    temp = sessionHead;
    while (temp != NULL) {
        if (strcmp(temp->username, usernameToLogout) == 0) {
            found = true;
            break;
        }
        temp = temp->next;
    }

    if (!found) {
        cout << " User '" << usernameToLogout << "' is not currently logged in!" << endl;
        return;
    }

    // Update user active status FIRST
    for (int i = 0; i < userCount; i++) {
        if (strcmp(users[i].username, usernameToLogout) == 0) {
            users[i].isActive = false;
            break;
        }
    }

    // Remove from active sessions (this also removes from circular list)
    removeActiveSession(usernameToLogout);

    // Update currentLoggedInUser intelligently
    if (strcmp(currentLoggedInUser, usernameToLogout) == 0) {
        // If we're logging out the current user, switch to another active user
        if (sessionHead != NULL) {
            // Switch to the first user in the session list
            strcpy(currentLoggedInUser, sessionHead->username);
            cout << " Current active user switched to: " << currentLoggedInUser << endl;
        } else {
            // No users left
            currentLoggedInUser[0] = '\0';
        }
    }

    cout << "\n User '" << usernameToLogout << "' logged out successfully!" << endl;
}

// ==================== MAIN MENU ====================

void displayMenu() {
    cout << " CYBER SECURITY MONITORING & ANALYSIS SYSTEM" << endl;

    if (strlen(currentLoggedInUser) > 0) {
        cout << "  Logged in as: " << currentLoggedInUser << endl;
    } else {
        cout << "  Status: Not logged in" << endl;
    }

    cout << "\n1.  Register User" << endl;
    cout << "2.  Login User" << endl;
    cout << "3.  Logout User" << endl;
    cout << "4.  View Failed Login Attempts" << endl;
    cout << "5.  View Active Sessions " << endl;
    cout << "6.  Display Active Users Rotation " << endl;
    cout << "7.  Change Password" << endl;
    cout << "8.  View Password History" << endl;
    cout << "9.  Suspicious Activity Logs " << endl;
    cout << "10. Threat Priority Handling" << endl;
    cout << "11. Handle Top Priority Threat" << endl;
    cout << "12. Sort Logs" << endl;
    cout << "13. Display User Access Tree" << endl;
    cout << "14. Exit" << endl;
    cout << "\nEnter your choice: ";
}

int main() {
    int choice;

    cout << "     INITIALIZING CYBER SECURITY MONITORING SYSTEM" << endl;

    // Initialize dynamic array
    initializeDynamicArray();

    cout << "\n System initialized successfully!" << endl;
    pause();

    do {
        displayMenu();
        cin >> choice;

        switch(choice) {
            case 1:
                registerUser();
                pause();
                break;
            case 2:
                loginUser();
                pause();
                break;
            case 3:
                logoutUser();
                pause();
                break;
            case 4:
                viewFailedLoginAttempts();
                pause();
                break;
            case 5:
                viewActiveSessions();
                pause();
                break;
            case 6:
                displayActiveUsersRotation();
                pause();
                break;
            case 7:
                changePassword();
                pause();
                break;
            case 8:
                viewPasswordHistory();
                pause();
                break;
            case 9:
                viewSuspiciousActivityLogs();
                pause();
                break;
            case 10:
                viewThreatPriorityQueue();
                pause();
                break;
            case 11:
                handleTopThreat();
                pause();
                break;
            case 12:
                sortLogsMenu();
                pause();
                break;
            case 13:
                displayUserAccessTree();
                pause();
                break;
            case 14:
                cout << "  EXITING CYBER SECURITY MONITORING SYSTEM" << endl;
                cout << "\n Thank you for using the system!" << endl;
                cout << "\nFinal Statistics:" << endl;
                cout << "- Total Registered Users: " << userCount << endl;
                cout << "- Current Array Capacity: " << userCapacity << endl;

                // Cleanup
                if (users != NULL) {
                    delete[] users;
                }

                cout << "\n[SUCCESS] System shutdown complete." << endl;
                break;
            default:
                cout << "\n[ERROR] Invalid choice! Please enter a number between 1-14." << endl;
                pause();
        }

    } while (choice != 14);

    return 0;
}
