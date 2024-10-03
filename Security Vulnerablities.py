import hashlib

class BankAccount:
    def _init_(self, account_number, password):
        self.account_number = account_number
        self.password = self.hash_password(password)  # Hashing the password
        self.balance = 0.0

    # Simple hashing using SHA-256 (for demonstration purposes)
    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()

    # Verify the hashed password
    def authenticate(self, entered_password):
        return self.password == self.hash_password(entered_password)

    def deposit(self, amount):
        if amount > 0:
            self.balance += amount
            print(f"${amount} deposited successfully.")
        else:
            print("Invalid deposit amount.")

    def withdraw(self, amount):
        if 0 < amount <= self.balance:
            self.balance -= amount
            print(f"${amount} withdrawn successfully.")
        else:
            print("Invalid or insufficient balance.")

    def check_balance(self):
        print(f"Current balance: ${self.balance}")


class SimpleBankingSystem:
    def _init_(self):
        self.accounts = {}

    def create_account(self):
        account_number = input("Enter account number: ")
        if account_number in self.accounts:
            print("Account already exists.")
            return

        password = input("Enter password: ")
        if len(password) < 6:
            print("Password must be at least 6 characters long.")
            return

        self.accounts[account_number] = BankAccount(account_number, password)
        print("Account created successfully!")

    def login(self):
        account_number = input("Enter account number: ")
        password = input("Enter password: ")

        account = self.accounts.get(account_number)

        if account and account.authenticate(password):
            print("Login successful!")
            self.account_menu(account)
        else:
            print("Invalid account number or password.")

    def account_menu(self, account):
        while True:
            print("\n1. Check Balance\n2. Deposit\n3. Withdraw\n4. Logout")
            choice = input("Choose an option: ")

            if choice == '1':
                account.check_balance()
            elif choice == '2':
                amount = float(input("Enter deposit amount: "))
                account.deposit(amount)
            elif choice == '3':
                amount = float(input("Enter withdrawal amount: "))
                account.withdraw(amount)
            elif choice == '4':
                print("Logged out.")
                break
            else:
                print("Invalid option.")


def main():
    system = SimpleBankingSystem()
    while True:
        print("\n1. Create Account\n2. Login\n3. Exit")
        choice = input("Choose an option: ")

        if choice == '1':
            system.create_account()
        elif choice == '2':
            system.login()
        elif choice == '3':
            print("Exiting system.")
            break
        else:
            print("Invalid option.")

if __name__ == "__main__":
    main()
