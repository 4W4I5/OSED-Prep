import colorama
from colorama import Back, Fore, Style

# Initialize colorama to work on Windows as well
colorama.init(autoreset=True)


def create_color_palette():
    # Define color lists
    fore_colors = {
        "Black": Fore.BLACK,
        "L_Black": Fore.LIGHTBLACK_EX,
        "Red": Fore.RED,
        "L_Red": Fore.LIGHTRED_EX,
        "Green": Fore.GREEN,
        "L_Green": Fore.LIGHTGREEN_EX,
        "Yellow": Fore.YELLOW,
        "L_Yellow": Fore.LIGHTYELLOW_EX,
        "Blue": Fore.BLUE,
        "L_Blue": Fore.LIGHTBLUE_EX,
        "Magenta": Fore.MAGENTA,
        "L_Magenta": Fore.LIGHTMAGENTA_EX,
        "Cyan": Fore.CYAN,
        "L_Cyan": Fore.LIGHTCYAN_EX,
        "White": Fore.WHITE,
        "L_White": Fore.LIGHTWHITE_EX,
    }
    back_colors = {
        "Black": Back.BLACK,
        "L_Black": Back.LIGHTBLACK_EX,
        "Red": Back.RED,
        "L_Red": Back.LIGHTRED_EX,
        "Green": Back.GREEN,
        "L_Green": Back.LIGHTGREEN_EX,
        "Yellow": Back.YELLOW,
        "L_Yellow": Back.LIGHTYELLOW_EX,
        "Blue": Back.BLUE,
        "L_Blue": Back.LIGHTBLUE_EX,
        "L_Magenta": Back.LIGHTMAGENTA_EX,
        "L_Cyan": Back.LIGHTCYAN_EX,
        "White": Back.WHITE,
        "L_White": Back.LIGHTWHITE_EX,
    }
    styles = {"Dim": Style.DIM, "Normal": Style.NORMAL, "Bright": Style.BRIGHT}

    print("\n--- Colorama Color Grid Palette ---\n")

    # Header
    print(f"{' ':12}", end="")
    for name in fore_colors.keys():
        print(f"{name:10}", end="")
    print("\n" + "-" * 90)

    # Grid generation
    for s_name, s_code in styles.items():
        print(f"\n{s_name} Style:\n")
        for b_name, b_code in back_colors.items():
            # Print row label
            print(f"{b_name:10}", end="")

            for f_name, f_code in fore_colors.items():
                # Combine style, background, and foreground
                cell = f"{s_code}{b_code}{f_code} [Sample] "
                print(f"{cell:16}", end="")  # 16 accounts for hidden ANSI chars
            print()  # New line
        print("-" * 90)


if __name__ == "__main__":
    create_color_palette()
