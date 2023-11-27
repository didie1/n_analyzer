import importlib
import subprocess

def check_installation(package_name):
    """
    Check if a Python package is installed.

    Parameters:
    - package_name (str): The name of the Python package to check.

    Returns:
    - bool: True if the package is installed, False otherwise.
    """
    try:
        is_searchsploit_installed()
        importlib.import_module(package_name)
        print(f"{package_name} is installed.")
        return True
    except ImportError:
        print(f"{package_name} is not installed.")
        return False

def install_package(package_name):
    """
    Install a Python package using pip.

    Parameters:
    - package_name (str): The name of the Python package to install.

    Returns:
    - bool: True if the package is successfully installed, False otherwise.
    """
    try:
        subprocess.run(["pip", "install", package_name], check=True)
        print(f"{package_name} has been successfully installed.")
        return True
    except subprocess.CalledProcessError:
        print(f"Failed to install {package_name}. Please install it manually.")
        return False

def ask_installation(libraries):
    """
    Ask the user whether to install missing Python libraries.

    Parameters:
    - libraries (list): A list of Python library names.

    Returns:
    - None
    """
    missing_libraries = [lib for lib in libraries if not check_installation(lib)]

    if missing_libraries:
        install_libraries = input(f"Do you want to install the following libraries? {', '.join(missing_libraries)} (y/n): ").lower()

        if install_libraries == "y":
            for lib in missing_libraries:
               #install_package(lib)
                if lib == 'searchsploit':
                    install_searchsploit()
                else: 
                    install_package(lib)
        else:
            print("Required libraries are not installed. Exiting.")
            exit()
    else:
        print("All required libraries are already installed.")

def is_kali_linux():
    """
    Check if the system is running on Kali Linux.

    Returns:
    - bool: True if the system is Kali Linux, False otherwise.
    """
    try:
        release_output = subprocess.check_output("lsb_release -si", shell=True, text=True).strip()
        return release_output.lower() == "kali"
    except subprocess.CalledProcessError:
        return False

def is_searchsploit_installed():
    """
    Check if searchsploit is available in the system.

    Returns:
    - bool: True if searchsploit is installed, False otherwise.
    """
    try:
        subprocess.check_output("command -v searchsploit", shell=True)
        return True
    except subprocess.CalledProcessError:
        return False

def install_exploitdb():
    """
    Install Exploit Database by cloning the repository.

    Returns:
    - None
    """
    clone_command = "git clone https://gitlab.com/exploit-database/exploitdb.git /opt/exploit-database"
    subprocess.run(clone_command, shell=True, check=True)

def add_searchsploit_to_path():
    """
    Add SearchSploit to $PATH by creating a symbolic link.

    Returns:
    - None
    """
    link_command = "ln -sf /opt/exploit-database/searchsploit /usr/local/bin/searchsploit"
    subprocess.run(link_command, shell=True, check=True)

def copy_searchsploit_rc():
    """
    Copy and edit the SearchSploit resource file.

    Returns:
    - None
    """
    copy_command = "cp -n /opt/exploit-database/.searchsploit_rc ~/.searchsploit_rc"
    subprocess.run(copy_command, shell=True, check=True)

    edit_command = "vim ~/.searchsploit_rc"
    subprocess.run(edit_command, shell=True, check=True)

def install_searchsploit():
    """
    Install SearchSploit by performing necessary steps.

    Returns:
    - None
    """
    try:
        if is_searchsploit_installed():
            print("SearchSploit is already installed. No need to install.")
            return

        print("\nStep 1: Cloning Exploit Database repository...")
        install_exploitdb()

        print("\nStep 2: Adding SearchSploit to $PATH...")
        add_searchsploit_to_path()

        print("\nStep 3: Copying and editing the resource file...")
        copy_searchsploit_rc()

        print("\nSearchSploit installation completed successfully!")
    except subprocess.CalledProcessError as e:
        print(f"Error during SearchSploit installation: {e}")
        exit()
    except Exception as e:
        print(f"An unexpected error occurred during SearchSploit installation: {e}")
        exit()

# List of required libraries
required_libraries = ["searchsploit", "pony.orm", "jinja2", "weasyprint"]

ask_installation(required_libraries)
