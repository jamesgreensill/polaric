import os
import subprocess
import sys
import argparse

def create_virtual_environment(venv_directory):
    """Create a virtual environment."""
    print("Creating virtual environment...")
    subprocess.run([sys.executable, "-m", "venv", venv_directory], check=True)
    print(f"Virtual environment created in {venv_directory}")

def activate_and_install_dependencies(os_name, venv_directory, requirements_file):
    """Activate the virtual environment and install dependencies."""
    print("Activating virtual environment...")
    
    activate_script = (
        f"{venv_directory}/Scripts/activate" if os_name == "nt" 
        else f"source {venv_directory}/bin/activate"
    )
    command = f"{activate_script} && pip3 install -r {requirements_file}"

    try:
        subprocess.run(
            command, 
            shell=True, 
            check=True, 
            executable=None if os_name == "nt" else "/bin/bash"
        )
        print("Dependencies installed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error installing dependencies: {e}")

def deactivate_virtual_environment(os_name):
    """Deactivate the virtual environment."""
    print("Deactivating virtual environment...")
    if os_name != "nt":
        subprocess.run("deactivate", shell=True, executable="/bin/bash")

def install():
    """Parse arguments, create a virtual environment, and install dependencies."""
    parser = argparse.ArgumentParser(prog="Project Installer")
    parser.add_argument("-r", "--requirements", help="Path to requirements file", default="requirements.txt")
    parser.add_argument("-v", "--venv", help="Path to virtual environment directory", default=".v")
    args = parser.parse_args()

    os_name = os.name
    requirements_file = args.requirements
    venv_directory = args.venv

    create_virtual_environment(venv_directory)
    activate_and_install_dependencies(os_name, venv_directory, requirements_file)
    deactivate_virtual_environment(os_name)

def main():
    install()

if __name__ == "__main__":
    main()

