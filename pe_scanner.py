"""
pe_scanner.py
─────────────────────────────────────────────────────────────
SecureAI — PE (Windows Executable) Malware Scanner

HOW IT WORKS:
  1. User uploads a .exe / .dll / .sys file
  2. We read the PE header using the 'pefile' library
  3. We extract 54 numeric features (sizes, counts, entropy values)
  4. Those 54 numbers go into our trained Random Forest model
  5. The model outputs: malware or benign + confidence %
  6. We also return "risk signals" — plain-English reasons

WHAT IS A PE FILE?
  Every Windows .exe and .dll is a "Portable Executable".
  It has a structured header that tells Windows how to run it.
  Malware has predictable patterns in that header (high entropy,
  weird DLL counts, suspicious section sizes) that our model
  learned to detect from 138,000 training examples.
"""

import pefile       # reads Windows .exe/.dll structure
import math
import array
import os
import logging
import joblib       # loads the saved .pkl model
import pickle
import pandas as pd

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────
# HELPER FUNCTIONS  (adapted from PE_main.py in the reference repo)
# These are the same logic used to BUILD the training dataset,
# so they must stay identical for predictions to be accurate.
# ─────────────────────────────────────────────────────────────

def _get_entropy(data: bytes) -> float:
    """
    Shannon entropy of a byte sequence.
    Range: 0.0 (all same byte) → 8.0 (perfectly random).
    Packed/encrypted malware sections are usually > 7.0.
    """
    if len(data) == 0:
        return 0.0
    counts = array.array('L', [0] * 256)
    for byte in data:
        counts[byte if isinstance(byte, int) else ord(byte)] += 1
    entropy = 0.0
    for c in counts:
        if c:
            p = float(c) / len(data)
            entropy -= p * math.log(p, 2)
    return entropy


def _get_resources(pe: pefile.PE) -> list:
    """
    Extract [entropy, size] pairs for every embedded resource.
    Malware often hides payloads inside PE resources.
    """
    resources = []
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        try:
            for rtype in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(rtype, 'directory'):
                    for rid in rtype.directory.entries:
                        if hasattr(rid, 'directory'):
                            for rlang in rid.directory.entries:
                                data = pe.get_data(
                                    rlang.data.struct.OffsetToData,
                                    rlang.data.struct.Size
                                )
                                resources.append([_get_entropy(data), rlang.data.struct.Size])
        except Exception:
            pass
    return resources


def _extract_pe_features(file_path: str) -> dict:
    """
    Extract all 54 PE header features from a file.
    Returns a dict with the same column names as the training dataset.
    Raises pefile.PEFormatError if the file is not a valid PE.
    """
    pe = pefile.PE(file_path)
    res = {}

    # ── FILE HEADER ────────────────────────────────────────────
    res['Machine']               = pe.FILE_HEADER.Machine
    res['SizeOfOptionalHeader']  = pe.FILE_HEADER.SizeOfOptionalHeader
    res['Characteristics']       = pe.FILE_HEADER.Characteristics

    # ── OPTIONAL HEADER ────────────────────────────────────────
    res['MajorLinkerVersion']            = pe.OPTIONAL_HEADER.MajorLinkerVersion
    res['MinorLinkerVersion']            = pe.OPTIONAL_HEADER.MinorLinkerVersion
    res['SizeOfCode']                    = pe.OPTIONAL_HEADER.SizeOfCode
    res['SizeOfInitializedData']         = pe.OPTIONAL_HEADER.SizeOfInitializedData
    res['SizeOfUninitializedData']       = pe.OPTIONAL_HEADER.SizeOfUninitializedData
    res['AddressOfEntryPoint']           = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    res['BaseOfCode']                    = pe.OPTIONAL_HEADER.BaseOfCode
    try:
        res['BaseOfData'] = pe.OPTIONAL_HEADER.BaseOfData
    except AttributeError:
        res['BaseOfData'] = 0   # 64-bit PEs don't have BaseOfData
    res['ImageBase']                     = pe.OPTIONAL_HEADER.ImageBase
    res['SectionAlignment']              = pe.OPTIONAL_HEADER.SectionAlignment
    res['FileAlignment']                 = pe.OPTIONAL_HEADER.FileAlignment
    res['MajorOperatingSystemVersion']   = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
    res['MinorOperatingSystemVersion']   = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
    res['MajorImageVersion']             = pe.OPTIONAL_HEADER.MajorImageVersion
    res['MinorImageVersion']             = pe.OPTIONAL_HEADER.MinorImageVersion
    res['MajorSubsystemVersion']         = pe.OPTIONAL_HEADER.MajorSubsystemVersion
    res['MinorSubsystemVersion']         = pe.OPTIONAL_HEADER.MinorSubsystemVersion
    res['SizeOfImage']                   = pe.OPTIONAL_HEADER.SizeOfImage
    res['SizeOfHeaders']                 = pe.OPTIONAL_HEADER.SizeOfHeaders
    res['CheckSum']                      = pe.OPTIONAL_HEADER.CheckSum
    res['Subsystem']                     = pe.OPTIONAL_HEADER.Subsystem
    res['DllCharacteristics']            = pe.OPTIONAL_HEADER.DllCharacteristics
    res['SizeOfStackReserve']            = pe.OPTIONAL_HEADER.SizeOfStackReserve
    res['SizeOfStackCommit']             = pe.OPTIONAL_HEADER.SizeOfStackCommit
    res['SizeOfHeapReserve']             = pe.OPTIONAL_HEADER.SizeOfHeapReserve
    res['SizeOfHeapCommit']              = pe.OPTIONAL_HEADER.SizeOfHeapCommit
    res['LoaderFlags']                   = pe.OPTIONAL_HEADER.LoaderFlags
    res['NumberOfRvaAndSizes']           = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes

    # ── SECTIONS ───────────────────────────────────────────────
    res['SectionsNb'] = len(pe.sections)
    entropies    = [s.get_entropy()     for s in pe.sections]
    raw_sizes    = [s.SizeOfRawData     for s in pe.sections]
    virt_sizes   = [s.Misc_VirtualSize  for s in pe.sections]

    res['SectionsMeanEntropy']    = sum(entropies) / len(entropies)
    res['SectionsMinEntropy']     = min(entropies)
    res['SectionsMaxEntropy']     = max(entropies)
    res['SectionsMeanRawsize']    = sum(raw_sizes) / len(raw_sizes)
    res['SectionsMinRawsize']     = min(raw_sizes)
    res['SectionMaxRawsize']      = max(raw_sizes)
    res['SectionsMeanVirtualsize'] = sum(virt_sizes) / len(virt_sizes)
    res['SectionsMinVirtualsize'] = min(virt_sizes)
    res['SectionMaxVirtualsize']  = max(virt_sizes)

    # ── IMPORTS ────────────────────────────────────────────────
    try:
        res['ImportsNbDLL']     = len(pe.DIRECTORY_ENTRY_IMPORT)
        all_imports             = sum([x.imports for x in pe.DIRECTORY_ENTRY_IMPORT], [])
        res['ImportsNb']        = len(all_imports)
        res['ImportsNbOrdinal'] = 0
    except AttributeError:
        res['ImportsNbDLL']     = 0
        res['ImportsNb']        = 0
        res['ImportsNbOrdinal'] = 0

    # ── EXPORTS ────────────────────────────────────────────────
    try:
        res['ExportNb'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
    except AttributeError:
        res['ExportNb'] = 0

    # ── RESOURCES ──────────────────────────────────────────────
    resources = _get_resources(pe)
    res['ResourcesNb'] = len(resources)
    if resources:
        entropies_r = [r[0] for r in resources]
        sizes_r     = [r[1] for r in resources]
        res['ResourcesMeanEntropy'] = sum(entropies_r) / len(entropies_r)
        res['ResourcesMinEntropy']  = min(entropies_r)
        res['ResourcesMaxEntropy']  = max(entropies_r)
        res['ResourcesMeanSize']    = sum(sizes_r) / len(sizes_r)
        res['ResourcesMinSize']     = min(sizes_r)
        res['ResourcesMaxSize']     = max(sizes_r)
    else:
        res['ResourcesMeanEntropy'] = 0
        res['ResourcesMinEntropy']  = 0
        res['ResourcesMaxEntropy']  = 0
        res['ResourcesMeanSize']    = 0
        res['ResourcesMinSize']     = 0
        res['ResourcesMaxSize']     = 0

    # ── LOAD CONFIGURATION ─────────────────────────────────────
    try:
        res['LoadConfigurationSize'] = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size
    except AttributeError:
        res['LoadConfigurationSize'] = 0

    # ── VERSION INFORMATION ────────────────────────────────────
    try:
        ver_info = {}
        for fi in pe.FileInfo:
            if fi.Key == b'StringFileInfo':
                for st in fi.StringTable:
                    for entry in st.entries.items():
                        ver_info[entry[0]] = entry[1]
        res['VersionInformationSize'] = len(ver_info.keys())
    except AttributeError:
        res['VersionInformationSize'] = 0

    pe.close()
    return res


# ─────────────────────────────────────────────────────────────
# RISK SIGNAL RULES
# These are plain-English explanations written AFTER prediction.
# They help the user understand WHY the file was flagged.
# ─────────────────────────────────────────────────────────────

def _build_risk_signals(features: dict) -> list:
    """
    Return a list of human-readable strings explaining suspicious indicators.
    Based on the top feature importances discovered during training.
    """
    signals = []

    max_entropy = features.get('SectionsMaxEntropy', 0)
    res_max_entropy = features.get('ResourcesMaxEntropy', 0)
    imports_dll = features.get('ImportsNbDLL', 0)
    imports_nb  = features.get('ImportsNb', 0)
    sections_nb = features.get('SectionsNb', 0)
    checksum    = features.get('CheckSum', 1)

    if max_entropy > 7.2:
        signals.append(
            f"High section entropy ({max_entropy:.2f}/8.0) — file sections appear "
            f"packed or encrypted, a common malware obfuscation technique."
        )
    if res_max_entropy > 7.2:
        signals.append(
            f"High resource entropy ({res_max_entropy:.2f}/8.0) — embedded resources "
            f"look encrypted, malware often hides payloads in PE resources."
        )
    if imports_dll > 12:
        signals.append(
            f"Unusually high DLL import count ({imports_dll}) — importing many DLLs "
            f"can indicate broad Windows API usage typical of malware."
        )
    if imports_nb > 200:
        signals.append(
            f"Large total import count ({imports_nb} functions) — complex import table "
            f"may indicate advanced capabilities or code injection tools."
        )
    if sections_nb > 7:
        signals.append(
            f"High section count ({sections_nb}) — many PE sections can indicate "
            f"a packer that added extra encrypted/stub sections."
        )
    if checksum == 0:
        signals.append(
            "CheckSum is zero — legitimate signed Windows files always have a non-zero "
            "checksum; zero often means the file is unsigned or tampered."
        )

    return signals


# ─────────────────────────────────────────────────────────────
# MAIN CLASS
# ─────────────────────────────────────────────────────────────

class PEScanner:
    """
    Loads the trained Random Forest model and scans PE files.
    Usage:
        scanner = PEScanner()
        scanner.load_model("pe_model.pkl", "pe_features.pkl")
        result  = scanner.predict("/path/to/file.exe")
    """

    def __init__(self):
        self.model         = None
        self.feature_names = None

    def load_model(self, model_path: str, features_path: str):
        """Load the .pkl model and feature name list from disk."""
        try:
            self.model         = joblib.load(model_path)
            self.feature_names = pickle.load(open(features_path, 'rb'))
            logger.info(f"PE scanner model loaded. Expects {len(self.feature_names)} features.")
        except FileNotFoundError as e:
            logger.error(f"Model file not found: {e}. Run step1_train.py first.")
            raise
        except Exception as e:
            logger.error(f"Error loading PE model: {e}")
            raise

    def predict(self, file_path: str) -> dict:
        """
        Main method: extract features from file, run model, return result dict.

        Returns:
            {
                "verdict":       "malware" | "benign",
                "confidence":    97.4,          # percentage 0–100
                "features":      { ... },       # all 54 extracted values
                "risk_signals":  [ "...", ... ] # plain-English explanations
            }
        """
        if self.model is None:
            raise RuntimeError("Model not loaded. Call load_model() first.")

        # ── Extract features ───────────────────────────────────
        try:
            features_dict = _extract_pe_features(file_path)
        except pefile.PEFormatError:
            raise ValueError("File is not a valid PE (Windows executable). "
                             "Only .exe, .dll, .sys files are supported.")
        except Exception as e:
            raise RuntimeError(f"Feature extraction failed: {e}")

        # ── Arrange features in the EXACT training order ───────
        # If a feature is missing for some reason, default to 0
        values = [features_dict.get(f, 0) for f in self.feature_names]
        df = pd.DataFrame([values], columns=self.feature_names)

        # ── Model prediction ───────────────────────────────────
        prediction  = self.model.predict(df)[0]          # 0 = benign, 1 = malware
        probability = self.model.predict_proba(df)[0]    # [p_benign, p_malware]
        confidence  = round(float(max(probability)) * 100, 2)

        verdict = "malware" if prediction == 1 else "benign"

        # ── Build risk signals ─────────────────────────────────
        risk_signals = _build_risk_signals(features_dict)

        # If benign but there are still some warning signals, label them as informational
        if verdict == "benign" and risk_signals:
            risk_signals = [f"[INFO] {s}" for s in risk_signals]

        logger.info(f"PE scan result: {verdict} ({confidence}%) for {os.path.basename(file_path)}")

        filtered_features = {k: features_dict[k] for k in self.feature_names if k in features_dict}

        return {
            "verdict":      verdict,
            "confidence":   confidence,
            "features":     filtered_features,
            "risk_signals": risk_signals
        }


# ─────────────────────────────────────────────────────────────
# Global singleton — imported and used in routes.py
# ─────────────────────────────────────────────────────────────
pe_scanner = PEScanner()
