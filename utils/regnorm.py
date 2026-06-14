# utils/regnorm.py

def normalise_reg(reg: str) -> str:
    """
    Normalise an aircraft registration for consistent lookup.
    Example: 'OO-ABC' -> 'OOABC'
    """
    if not reg:
        return ""
    reg = reg.strip().upper()
    reg = reg.replace("-", "")
    reg = reg.replace(" ", "")
    return reg
