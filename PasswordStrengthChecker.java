import java.util.*;

public class PasswordStrengthChecker {

    // List of common weak passwords
    static String[] commonPasswords = {
        "123456", "password", "qwerty", "abc123",
        "admin", "welcome", "letmein", "12345678"
    };

    // Check if password is common
    public static boolean isCommonPassword(String password) {
        for (String p : commonPasswords) {
            if (password.equalsIgnoreCase(p)) {
                return true;
            }
        }
        return false;
    }

    // Calculate entropy
    public static double calculateEntropy(String password) {
        int charsetSize = 0;

        if (password.matches(".*[a-z].*"))
            charsetSize += 26;

        if (password.matches(".*[A-Z].*"))
            charsetSize += 26;

        if (password.matches(".*[0-9].*"))
            charsetSize += 10;

        if (password.matches(".*[^a-zA-Z0-9].*"))
            charsetSize += 32;

        if (charsetSize == 0)
            return 0;

        return password.length() * (Math.log(charsetSize) / Math.log(2));
    }

    // Check password policy
    public static void checkPolicy(String password) {

        boolean length = password.length() >= 8;
        boolean upper = password.matches(".*[A-Z].*");
        boolean lower = password.matches(".*[a-z].*");
        boolean digit = password.matches(".*[0-9].*");
        boolean special = password.matches(".*[^a-zA-Z0-9].*");

        System.out.println("\nPassword Policy Check");
        System.out.println("----------------------");
        System.out.println("Minimum Length (8): " + (length ? "Passed" : "Failed"));
        System.out.println("Uppercase Letter : " + (upper ? "Passed" : "Failed"));
        System.out.println("Lowercase Letter : " + (lower ? "Passed" : "Failed"));
        System.out.println("Digit            : " + (digit ? "Passed" : "Failed"));
        System.out.println("Special Character: " + (special ? "Passed" : "Failed"));

        if (isCommonPassword(password)) {
            System.out.println("Dictionary Check : FAILED (Common Password)");
        } else {
            System.out.println("Dictionary Check : Passed");
        }
    }

    // Strength classification
    public static String classifyStrength(double entropy) {

        if (entropy < 28)
            return "Weak";
        else if (entropy < 50)
            return "Moderate";
        else if (entropy < 80)
            return "Strong";
        else
            return "Exceptional";
    }

    // Suggestions
    public static void suggestions(String password) {

        System.out.println("\nSuggestions:");

        if (password.length() < 8)
            System.out.println("- Increase password length to at least 8 characters.");

        if (!password.matches(".*[A-Z].*"))
            System.out.println("- Add uppercase letters.");

        if (!password.matches(".*[a-z].*"))
            System.out.println("- Add lowercase letters.");

        if (!password.matches(".*[0-9].*"))
            System.out.println("- Add digits.");

        if (!password.matches(".*[^a-zA-Z0-9].*"))
            System.out.println("- Add special characters.");

        if (isCommonPassword(password))
            System.out.println("- Avoid common dictionary passwords.");
    }

    public static void main(String[] args) {

        Scanner sc = new Scanner(System.in);

        System.out.println("======================================");
        System.out.println("     PASSWORD STRENGTH CHECKER");
        System.out.println("======================================");

        System.out.print("Enter Password: ");
        String password = sc.nextLine();

        checkPolicy(password);

        double entropy = calculateEntropy(password);

        System.out.printf("\nEntropy : %.2f bits\n", entropy);

        String strength = classifyStrength(entropy);

        System.out.println("Strength: " + strength);

        suggestions(password);

        sc.close();
    }
}