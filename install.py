import os
import subprocess
import sys
import argparse

def install_requirements():
    parser = argparse.ArgumentParser(
        prog="Project Installer",
    )
    parser.add_argument("-r", "--requirements", help="Requirements File")
    parser.add_argument("-v", "--venv", help="Virtual Environment Location")
    
    args = parser.parse_args()
    
    os_name = os.name
    
    requirements_file = "requirements.txt" if args.requirements is None else args.requirements
    venv_directory = ".v" if args.venv is None else args.venv
    
    print("Creating virtual environment...")
    
    subprocess.run([sys.executable, "-m", "venv", venv_directory], check=True)
    
    print(f"Virtual environment created in {venv_directory}")

    print("Activating virtual environment...")
        
    activate_script = f"{venv_directory}/Scripts/activate" if os_name == "nt" else f"source {venv_directory}/bin/activate"
    command = f"{activate_script} && pip3 install -r {requirements_file}"
    try:
        match(os.name):
            case "nt":
                subprocess.run(command, shell=True, check=True)
                pass
            case _:
                subprocess.run(command, shell=True, executable="/bin/bash", check=True)
                pass
        print("Dependencies installed successfully.")
    except subprocess.CalledProcessError as e:
        print("Error installing dependencies:", e)

    print("Deactivating virtual environment...")
    
    if os.name != "nt":
        subprocess.run("deactivate", shell=True, executable="/bin/bash")

def main():
    install_requirements()
    pass

if __name__ == "__main__":
    main()