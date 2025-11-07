import subprocess
import os
import json
import tempfile
import shutil
import sys
from glob import glob

class ScannerRouter:
    def _find_npm_path(self):
        """Find npm executable path on Windows"""
        is_windows = os.name == 'nt'
        if is_windows:
            # Common npm installation paths on Windows
            possible_paths = [
                r"C:\Program Files\nodejs\npm.cmd",
                r"C:\Program Files (x86)\nodejs\npm.cmd",
                os.path.expanduser(r"~\AppData\Roaming\npm\npm.cmd"),
                "npm.cmd",  # If in PATH
                "npm"       # If in PATH (fallback)
            ]
            
            for path in possible_paths:
                try:
                    result = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        return path
                except (FileNotFoundError, subprocess.TimeoutExpired):
                    continue
        else:
            return "npm"
        
        raise FileNotFoundError("npm not found. Please install Node.js and npm.")

    def run_scan(self, repo_path: str, language: str):
        is_windows = os.name == 'nt'

        if language == "python":
            req_path = os.path.join(repo_path, "requirements.txt")
            if os.path.isfile(req_path):
                venv_dir = tempfile.mkdtemp(prefix="venv_")
                try:
                    subprocess.run([sys.executable, "-m", "venv", venv_dir], check=True, capture_output=True, text=True)

                    # Correct bin path depending on OS
                    bin_dir = "Scripts" if is_windows else "bin"
                    python_bin = os.path.join(venv_dir, bin_dir, "python.exe" if is_windows else "python")
                    pip_bin = os.path.join(venv_dir, bin_dir, "pip.exe" if is_windows else "pip")
                    audit_bin = os.path.join(venv_dir, bin_dir, "pip-audit.exe" if is_windows else "pip-audit")

                    # Upgrade pip first
                    subprocess.run([python_bin, "-m", "pip", "install", "--upgrade", "pip"], check=True, capture_output=True, text=True)
                    
                    # Try to install requirements with more lenient settings
                    install_result = subprocess.run([
                        pip_bin, "install", "-r", req_path, 
                        "--no-deps",  # Skip dependency resolution
                        "--ignore-requires-python",  # Ignore Python version requirements
                        "--disable-pip-version-check",
                        "--no-warn-script-location"
                    ], capture_output=True, text=True)
                    
                    # If install fails, try without --no-deps
                    if install_result.returncode != 0:
                        install_result = subprocess.run([
                            pip_bin, "install", "-r", req_path,
                            "--ignore-requires-python",
                            "--disable-pip-version-check",
                            "--no-warn-script-location",
                            "--force-reinstall"
                        ], capture_output=True, text=True)
                    
                    # If still failing, proceed with pip-audit installation anyway
                    subprocess.run([pip_bin, "install", "pip-audit", "requests", "beautifulsoup4"], check=True, capture_output=True, text=True)

                    if not os.path.isfile(audit_bin):
                        raise RuntimeError("pip-audit is not installed in the virtual environment.")

                    # Try pip-audit with requirements file first
                    result = subprocess.run([audit_bin, "-r", req_path, "-f", "json"], capture_output=True, text=True)
                    
                    # If that fails and we have some packages installed, try scanning the venv
                    if result.returncode != 0 and not result.stdout:
                        result = subprocess.run([audit_bin, "-f", "json"], cwd=venv_dir, capture_output=True, text=True)
                    
                    if result.stdout and result.stdout.strip():
                        try:
                            return json.loads(result.stdout)
                        except json.JSONDecodeError:
                            return {
                                "error": "pip-audit returned invalid JSON",
                                "raw_output": result.stdout[:1000],
                                "stderr": result.stderr[:1000] if result.stderr else None
                            }
                    else:
                        # Return empty result if no vulnerabilities found
                        return {
                            "vulnerabilities": [],
                            "metadata": {
                                "totalDependencies": 0,
                                "totalVulnerabilities": 0
                            }
                        }
                        
                except subprocess.CalledProcessError as e:
                    # If virtual environment setup fails, try system-wide pip-audit
                    try:
                        result = subprocess.run(["pip-audit", "-r", req_path, "-f", "json"], capture_output=True, text=True)
                        if result.stdout:
                            return json.loads(result.stdout)
                        else:
                            raise RuntimeError(f"pip-audit returned no output: {result.stderr}")
                    except (FileNotFoundError, subprocess.CalledProcessError, json.JSONDecodeError):
                        raise RuntimeError(f"Failed to install requirements and run pip-audit. Install error: {e.stderr}")
                finally:
                    shutil.rmtree(venv_dir, ignore_errors=True)
            else:
                try:
                    result = subprocess.run(["pip-audit", "-f", "json"], cwd=repo_path, capture_output=True, text=True)
                    if result.returncode != 0 and not result.stdout:
                        raise RuntimeError(f"pip-audit failed: {result.stderr}")
                    if result.stdout:
                        return json.loads(result.stdout)
                    else:
                        raise RuntimeError(f"pip-audit returned no output: {result.stderr}")
                except FileNotFoundError:
                    raise RuntimeError("pip-audit is not installed or not found in PATH.")
                except subprocess.CalledProcessError as e:
                    raise RuntimeError(f"pip-audit failed: {e.stderr}")
                except json.JSONDecodeError:
                    raise RuntimeError("pip-audit did not return valid JSON output.")

        elif language == "nodejs":
            pkg_json = os.path.join(repo_path, "package.json")
            if not os.path.isfile(pkg_json):
                raise FileNotFoundError("package.json not found in repo.")
            
            npm_cmd = "npm.cmd" if is_windows else "npm"
            
            try:
                # Set encoding to utf-8 and handle errors gracefully
                env = os.environ.copy()
                if is_windows:
                    env['PYTHONIOENCODING'] = 'utf-8'
                
                # Run npm install
                install_result = subprocess.run(
                    [npm_cmd, "install", "--ignore-scripts"], 
                    cwd=repo_path, 
                    capture_output=True, 
                    text=True, 
                    encoding='utf-8', 
                    errors='replace',  # Replace problematic characters
                    env=env,
                    check=True
                )
                
                # Run npm audit
                audit_result = subprocess.run(
                    [npm_cmd, "audit", "--json"], 
                    cwd=repo_path, 
                    capture_output=True, 
                    text=True, 
                    encoding='utf-8', 
                    errors='replace',  # Replace problematic characters
                    env=env
                )
                
                # Check if we got output
                if audit_result.stdout and audit_result.stdout.strip():
                    try:
                        return json.loads(audit_result.stdout)
                    except json.JSONDecodeError as json_err:
                        # If JSON parsing fails, return a structured error response
                        return {
                            "error": "JSON parsing failed",
                            "raw_output": audit_result.stdout[:1000],  # First 1000 chars
                            "stderr": audit_result.stderr[:1000] if audit_result.stderr else None
                        }
                else:
                    # If no stdout, check stderr or return empty result
                    if audit_result.stderr:
                        return {
                            "error": "npm audit returned no output",
                            "stderr": audit_result.stderr,
                            "returncode": audit_result.returncode
                        }
                    else:
                        # No vulnerabilities found
                        return {
                            "vulnerabilities": [],
                            "metadata": {
                                "totalDependencies": 0,
                                "totalVulnerabilities": 0
                            }
                        }
                        
            except subprocess.CalledProcessError as e:
                # npm audit returns non-zero exit code when vulnerabilities are found
                if e.stdout and e.stdout.strip():
                    try:
                        return json.loads(e.stdout)
                    except json.JSONDecodeError:
                        return {
                            "error": "npm audit failed with invalid JSON",
                            "raw_output": e.stdout[:1000] if e.stdout else None,
                            "stderr": e.stderr[:1000] if e.stderr else None,
                            "returncode": e.returncode
                        }
                else:
                    raise RuntimeError(f"npm audit failed: {e.stderr}")
            except UnicodeDecodeError as e:
                raise RuntimeError(f"Unicode decoding error: {str(e)}. Try running npm audit manually to check output.")
            except Exception as e:
                raise RuntimeError(f"Unexpected error during npm audit: {str(e)}")

        else:
            manifest_patterns = [
                "**/go.mod", "**/go.sum",
                "**/pom.xml", "**/build.gradle", "**/build.gradle.kts", "**/settings.gradle", "**/settings.gradle.kts",
                "**/Cargo.lock",
                "**/Gemfile.lock",
                "**/composer.lock",
                "**/pubspec.lock",
                "**/Pipfile.lock", "**/poetry.lock",
                "**/yarn.lock", "**/pnpm-lock.yaml", "**/package-lock.json",
                "**/*.csproj", "**/*.fsproj", "**/*.vbproj", "**/packages.config",
                "**/mix.lock",
                "**/shard.lock",
                "**/conan.lock",
                "**/requirements.txt"
            ]

            found_files = []
            for pattern in manifest_patterns:
                found_files.extend(glob(os.path.join(repo_path, pattern), recursive=True))
            if not found_files:
                raise NotImplementedError("No supported manifest/lockfiles found for OSV-Scanner.")

            try:
                # osv_path = r"C:\Program Files\osv-scanner\osv-scanner.exe" if is_windows else "osv-scanner"
                result = subprocess.run(
                    [r"C:\Program Files\osv-scanner\osv-scanner.exe", "--format", "json", *[f for file in found_files for f in ("--lockfile", file)]],
                    capture_output=True, text=True, check=True
                )
                return json.loads(result.stdout)
            except FileNotFoundError:
                raise RuntimeError("osv-scanner is not installed or not found in PATH.")
            except subprocess.CalledProcessError as e:
                if e.stdout:
                    return json.loads(e.stdout)
                raise RuntimeError(f"osv-scanner failed: {e.stderr}")
            except json.JSONDecodeError:
                raise RuntimeError("osv-scanner did not return valid JSON output.")