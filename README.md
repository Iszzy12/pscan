Network Scanner with Shodan Integration
This project is a network scanner application built with Python using Tkinter for the graphical user interface (GUI) and Shodan for retrieving security insights about a given IP address. The tool allows you to scan a range of ports on a target IP address and retrieve detailed information about open services using Shodan.

Features
Scan a range of ports (TCP/UDP) on a target IP.
Retrieve information about open services using the Shodan API, including vulnerabilities if available.
Display the results in an organized table within the GUI.
Ability to input an IP address and specify the port range to scan.
Requirements
Python 3.x
Tkinter (comes pre-installed with Python)
Shodan Python library (can be installed using pip)
Optional: python-dotenv for environment variable management
Installation
Clone this repository:

bash
Copy code
git clone https://github.com/yourusername/network-scanner.git
cd network-scanner
Install required libraries: Use pip to install the necessary dependencies:

Copy code
pip install -r requirements.txt
If you're using the .env file for API key management, install python-dotenv:

Copy code
pip install python-dotenv
API Key Configuration:

Create a .env file in the root of the project folder.
Add your Shodan API key in the .env file like this:
makefile
Copy code
SHODAN_API_KEY=your_shodan_api_key_here
Run the Program: Run the Python script:

Copy code
python network_scanner.py
The GUI will open, and you can start scanning ports and retrieving Shodan information.

Usage
Enter the target IP address in the input field.
Specify the start and end ports for the scan.
Select the protocol (TCP/UDP).
Click Submit to begin the scan.
The results will be displayed in a table, showing:

Port number
Service running on that port
Protocol type (TCP/UDP)
Vulnerabilities (if found) from Shodan.
Contributing
Feel free to fork this project and make contributions. Open an issue or create a pull request if you have any suggestions or improvements.

License
This project is open-source and available under the MIT License.

Acknowledgments
Shodan API for providing detailed information about devices on the internet.
Tkinter for creating the GUI.
Python for the foundation of the project.
