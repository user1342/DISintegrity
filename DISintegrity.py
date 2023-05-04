import os
import re
import shutil
import subprocess
import webbrowser
import argparse
from jinja2 import Template
from tqdm import tqdm

def get_strings_from_binary(binary_file):
    # Define a regular expression to match printable ASCII characters
    printable_regex = re.compile(rb'[\x20-\x7E]{5,}')

    # Read the binary file into memory
    with open(binary_file, 'rb') as f:
        binary_data = f.read()

    # Search for printable strings in the binary data using the regular expression
    printable_strings = printable_regex.findall(binary_data)
    strings = []
    # Convert the byte strings to regular strings and print them
    for s in printable_strings:
        strings.append(s.decode('ascii'))

    return strings

def is_subpath(subpath, path):
    '''
    Simple function to identify if one path is a subpath of anouther. Used for only checking directories that are
    part of the class path.
    :return: boolean (True/ False)
    '''
    subpath = os.path.normpath(subpath)
    path = os.path.normpath(path)

    # Split subpath and path into components
    subpath_parts = subpath.split(os.sep)
    path_parts = path.split(os.sep)

    # Find subpath in path
    for i in range(len(path_parts) - len(subpath_parts) + 1):
        if path_parts[i:i + len(subpath_parts)] == subpath_parts:
            return True

    return False


def extract_apk(apk_file_path, output_dir, apk_tool_executable):
    """Use apktool to disassemble the APK file."""
    print("Extracting APK at '{}'. This may take some time...".format(apk_file_path))
    with subprocess.Popen([apk_tool_executable, "d", apk_file_path, "-o", output_dir], stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True) as process:
        stdout, stderr = process.communicate(input="\n")
        if process.returncode != 0:
            print("An error occurred while running apktool for APK:")
            print(stderr)
            exit(1)


def check_apktool_on_path():
    """Check if apktool is on the path and return the executable name."""
    if shutil.which("apktool.bat"):
        return "apktool.bat"
    elif shutil.which("apktool.sh"):
        return "apktool.sh"
    elif shutil.which("apktool"):
        return "apktool"
    else:
        return None


def run_apktool(apk_tool_executable, apk_file_path, output_dir):
    """Run apktool to disassemble the APK file."""
    print("Extracting APK at '{}'".format(apk_file_path))
    with subprocess.Popen([apk_tool_executable, "d", apk_file_path, "-o", output_dir], stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True) as process:
        # Wait for the process to finish and capture the console output
        stdout, stderr = process.communicate(input="\n")

        # Check if the command was successful
        if process.returncode != 0:
            print("An error occurred while running apktool:")
            print(stderr)
            exit(1)


def get_smali_files(apk_dir, allow_path):
    """Get a list of all SMALI files in the disassembled APK directory."""
    smali_files = []
    file_to_path_dict = {}
    for dirpath, dirnames, filenames in tqdm(os.walk(apk_dir), desc="Finding SMALI files"):
        if is_subpath(allow_path, dirpath):
            for filename in filenames:
                if filename.endswith(".smali"):
                    smali_files.append(os.path.join(dirpath, filename))
                    file_to_path_dict[filename] = dirpath
    return smali_files, file_to_path_dict

root_detection_keywords = [
    ("SafetyNet", "Google Play SafetyNet"),  # Google Play SafetyNet API for checking device integrity
    ("safetynet", "Google Play SafetyNet"),  # Same as above, but with lowercase
    ("Safety Detect", "Huawei Safety Detect"),  # Huawei's safety detection API for detecting rooted devices
    ("safetydetect", "Huawei Safety Detect"),  # Same as above, but with lowercase
    ("RootBeer", "RootBeer"),  # RootBeer library for detecting rooted devices
    ("rootbeer", "RootBeer"),  # Same as above, but with lowercase
    ("isDeviceRooted", "Proprietary"),  # Custom code to check if device is rooted
    ("isRooted", "Proprietary"),  # Same as above, but shorter
    ("RootChecker", "Proprietary"),  # Custom code for checking if device is rooted
    ("checkRoot", "Proprietary"),  # Same as above, but shorter
    ("detectRoot", "Proprietary"),  # Custom code for detecting rooted devices
    ("detectTamper", "Proprietary"),  # Custom code for detecting if app has been tampered with
    ("tamperDetection", "Proprietary"),  # Custom code for detecting if app has been tampered with
    ("detectEmulator", "Proprietary"),  # Custom code for detecting if app is running on an emulator
    ("checkEmulator", "Proprietary"),  # Same as above, but shorter
    ("isEmulator", "Proprietary"),  # Same as above, but shorter
    ("rootCheck", "Proprietary"),  # Custom code for checking if device is rooted
    ("rootDetection", "Proprietary"),  # Custom code for detecting rooted devices
    ("rootedDevice", "Proprietary"),  # Custom code for checking if device is rooted
    ("isDeviceCompromised", "Proprietary"),  # Custom code for checking if device is compromised
    ("rootConfirmation", "Proprietary"),  # Custom code for confirming if device is rooted
    ("rootStatus", "Proprietary"),  # Custom code for checking root status
    ("isDeviceJailbroken", "Proprietary"),  # Custom code for checking if device is jailbroken
    ("jailbreakDetection", "Proprietary"),  # Custom code for detecting jailbroken devices
    ("checkJailbreak", "Proprietary"),  # Same as above, but shorter
    ("detectJailbreak", "Proprietary"),  # Same as above, but shorter
    ("isDeviceSecure", "Proprietary"),  # Custom code for checking device security
    ("deviceIntegrity", "Proprietary"),  # Custom code for checking device integrity
    ("integrityCheck", "Proprietary"),  # Custom code for checking device integrity
    ("systemIntegrity", "Proprietary"),  # Custom code for checking system integrity
    ("suBinary", "Proprietary"),  # Custom code for checking if su binary is installed
    ("superuser", "Proprietary"),  # Custom code for checking if Superuser app is installed
    ("magisk", "Magisk"),  # Magisk root management tool
    ("MagiskHide", "Magisk"),  # Magisk feature for hiding root from apps
    ("magiskhide", "Magisk"),  # Magisk feature for hiding root from apps
    ("deviceRootStatus", "Proprietary"),  # Custom code for checking device root status
    ("rootScanner", "Proprietary"),  # Custom code for scanning device for root
    ("rootAnalyzer", "Proprietary"),  # Custom code for analyzing device for root
    ("rootAssessment", "Proprietary"),  # Custom code for assessing device for root
    ("rootGuard", "Proprietary"),  # Custom code for guarding against root access
    ("rootValidator", "Proprietary"),  # Custom code for validating root status
    ("jailbreakStatus", "Proprietary"),  # Custom code for checking jailbreak status
    ("jailbreakCheck", "Proprietary"),  # Custom code for checking if device is jailbroken
    ("jailbreakScanner", "Proprietary"),  # Custom code for scanning device for jailbreak
    ("jailbreakGuard", "Proprietary"),  # Custom code for guarding against jailbreak
    ("isRootPresent", "Proprietary"),  # Custom code for checking if root is present
    ("rootPresence", "Proprietary"),  # Custom code for checking root presence
    ("rootVerifier", "Proprietary"),  # Custom code for verifying root status
    ("jailbreakVerifier", "Proprietary"),  # Custom code for verifying jailbreak status
    ("rootRisk", "Proprietary"),  # Custom code for assessing risk of root access
    ("jailbreakRisk", "Proprietary"),  # Custom code for assessing risk of jailbreak
    ("rootProber", "Proprietary"),  # Custom code for probing device for root
    ("rootTest", "Proprietary"),  # Custom code for testing if device is rooted
    ("jailbreakTest", "Proprietary"),  # Custom code for testing if device is jailbroken
    ("rootDetectionCheck", "Proprietary"),  # Custom code for checking if root is detected
    ("rootcloak", "Proprietary"),  # Custom code for cloaking root from apps
    ("rootcloakplus", "Proprietary"),  # Custom code for cloaking root from apps
    ("daemonsu", "Proprietary"),  # Custom code for managing su binary
    ("jailbreakDetectionCheck", "Proprietary"),  # Custom code for checking if jailbreak is detected
]

def search_for_keywords(file_path, keywords):
    results = []
    with open(file_path, "r") as f:
        content = f.readlines()
        for i, line in enumerate(content):
            for keyword, check_type in keywords:
                if keyword in line:
                    results.append((i + 1, line.strip(), keyword, check_type))
    return results

def search_smali_files(smali_files, keywords):
    detected_files = []
    for smali_file in smali_files:
        keyword_results = search_for_keywords(smali_file, keywords)
        if keyword_results:
            detected_files.append((smali_file, keyword_results))
    return detected_files

def search_binary_files(apk_dir, keywords):
    detected_files = []
    for root, dirs, files in os.walk(apk_dir):
        for file in files:
            if file.endswith(('.so', '.dat')):
                file_path = os.path.join(root, file)
                with open(file_path, "rb") as f:
                    content = f.read()
                    for keyword, check_type in keywords:
                        if keyword.encode() in content:
                            detected_files.append((file_path, keyword, check_type))
                            break
    return detected_files

def create_html_file(detected_smali_files, detected_binary_files, output_dir):
    template_str = '''
<!DOCTYPE html>
<html>
<head>
    <title>DIS{integrity} - Root and Tamper Detection Checks</title>
    <style>
        .codeblock {
            background-color: #f0f0f0;
            padding: 10px;
            border-radius: 5px;
            margin: 5px;
        }

        .codeblock pre {
            white-space: pre-wrap;
            white-space: -moz-pre-wrap;
            white-space: -pre-wrap;
            white-space: -o-pre-wrap;
            word-wrap: break-word;
        }

        .content {
            display: none;
        }

    </style>
    <script>
        function toggle_visibility(content_id) {
            let content = document.getElementById(content_id);
            if (content.style.display === 'none') {
                content.style.display = 'block';
            } else {
                content.style.display = 'none';
            }
        }

        window.addEventListener('load', () => {
            const clickableItems = document.querySelectorAll('.clickable');
            clickableItems.forEach(item => {
                const contentId = item.dataset.contentId;
                const content = document.getElementById(contentId);
                if (content.style.display === 'block') {
                    item.classList.add('active');
                }
                item.addEventListener('click', () => {
                    toggle_visibility(contentId);
                    item.classList.toggle('active');
                });
            });
        });
    </script>
    <style>
        .clickable {
            cursor: pointer;
        }
        .clickable.active {
            font-weight: bold;
        }
        .content.binary {
            display: block;
        }
    </style>
</head>
<body style="font-family: Arial, sans-serif;">
    <h1>DIS{integrity} - Root and Tamper Detection Checks</h1>
    <h2>In SMALI files:</h2>43  
    <ul>
        {% for file, results in detected_smali_files.items() %}
        <li>
            <h3 class="clickable" data-content-id="{{ loop.index }}_content">{{ file }}</h3>
            <div id="{{ loop.index }}_content" class="content">
                {% for line_number, line, keyword, check_type, function_code in results %}
                <div>
                    <p><strong>Keyword:</strong> {{ keyword }}<br><strong>Check Type:</strong> {{ check_type }}</p>
                    <p>Line {{ line_number }}: {{ line }}</p>
                    <div class="codeblock">
                        <pre>{{ function_code }}</pre>
                    </div>
                </div>
                {% endfor %}
            </div>
        </li>
        {% endfor %}
    </ul>
    <h2>In binary files:</h2>
    {% if detected_binary_files %}
    <ul>
        {% for file, keywords in detected_binary_files.items() %}
            {% if keywords %}
            <li>
                <h3 class="clickable active" data-content-id="{{ loop.index }}_content">{{ file }}</h3>
                <div id="{{ loop.index }}_content" class="content binary">
                    {% for keyword, (count, check_type) in keywords.items() %}
                    <div>
                        <p><strong>Keyword:</strong> {{ keyword }}<br><strong>Check Type:</strong> {{ check_type }}<br><strong>Match count:</strong> {{ count }}</p>
                    </div>
                    {% endfor %}
                </div>
            </li>
            {% endif %}
        {% endfor %}
    </ul>
    {% else %}
    <p>No detections in binary files.</p>
    {% endif %}
</body>
</html>
    '''
    template = Template(template_str)
    html = template.render(detected_smali_files=detected_smali_files, detected_binary_files=detected_binary_files)

    with open(os.path.join(output_dir, 'output.html'), 'w', encoding='utf-8') as f:
        f.write(html)

    webbrowser.open_new_tab(os.path.join(output_dir, 'output.html'))
    print("Output file created at {}".format(os.path.join(output_dir, 'output.html')))
def detect_checks_in_smali_files(file_paths, keywords):
    detected_smali_files = {}

    for file_path in tqdm(file_paths, desc="Searching SMALI files"):
        with open(file_path, encoding='utf-8') as file:
            lines = file.readlines()

        current_function_code = []
        in_function = False

        for line_number, line in enumerate(lines, start=1):
            line = line.strip()

            if line.startswith(".method"):
                in_function = True
                current_function_code = [line]
            elif line.startswith(".end method"):
                in_function = False
                current_function_code.append(line)

            if in_function:
                current_function_code.append(line)

            for keyword, check_type in keywords:
                if keyword in line:
                    if file_path not in detected_smali_files:
                        detected_smali_files[file_path] = []

                    detected_smali_files[file_path].append(
                        (line_number, line, keyword, check_type, "\n".join(current_function_code))
                    )

    return detected_smali_files

def detect_checks_in_binary_files(binary_files, keywords):
    detected_binary_files = {}

    for binary_file in tqdm(binary_files, desc="Searching binary files"):

        if binary_file.endswith(".smali") or binary_file.endswith(".html") or binary_file.endswith(".txt"):
            continue

        strings = get_strings_from_binary(binary_file)
        file_keywords = {}
        for keyword, check_type in keywords:
            count = 0
            for string_in_binary in strings:
                if keyword in string_in_binary:
                    count += 1
            if count > 0:
                file_keywords[keyword] = (count, check_type)
        if file_keywords:
            detected_binary_files[binary_file] = file_keywords

    return detected_binary_files

def main(args):
    apk_tool_executable = args.apktool
    apk_file_path = args.apk_file_path
    output_dir = args.output_dir

    if not output_dir:
        output_dir = os.path.splitext(os.path.basename(apk_file_path))[0]

    if not apk_tool_executable:
        apk_tool_executable = check_apktool_on_path()
        if not apk_tool_executable:
            print("Apktool not found. Please provide the path to the apktool executable using --apktool.")
            exit(1)

    if not apk_tool_executable:
        print("Apktool not found. Please provide the path to the apktool executable using --apktool.")
        exit(1)

    extract_apk(apk_file_path, output_dir, apk_tool_executable)

    smali_files, file_to_path_dict = get_smali_files(output_dir, "smali")

    # Search for checks in SMALI files
    detected_smali_files = detect_checks_in_smali_files(smali_files, root_detection_keywords)

    # Search for checks in binary files
    binary_files = [os.path.join(dp, f) for dp, dn, filenames in os.walk(output_dir) for f in filenames]
    detected_binary_files = detect_checks_in_binary_files(binary_files, root_detection_keywords)

    # Print the results to the console
    #print_results(detected_smali_files, detected_binary_files)

    # Create the HTML file
    create_html_file(detected_smali_files,detected_binary_files, output_dir)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Detect root checks in Android APK files')
    parser.add_argument("-apk",'--apk_file_path', metavar='APK_FILE_PATH', type=str, help='the path to the APK file to analyze')
    parser.add_argument('-o', '--output-dir', metavar='OUTPUT_DIR', type=str,
                        help='the output directory to store the analysis results', required=False)
    parser.add_argument('--apktool', metavar='APKTOOL', type=str, help='the path to the apktool executable', required=False)
    args = parser.parse_args()

    main(args)