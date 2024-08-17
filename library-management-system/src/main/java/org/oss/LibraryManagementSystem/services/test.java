package org.oss.LibraryManagementSystem.services;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class test {
    private static BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    // Hash mật khẩu
    public static String hashPassword(String password) {
        return encoder.encode(password);
    }

    // Kiểm tra mật khẩu
    public static boolean checkPassword(String rawPassword, String encodedPassword) {
        return encoder.matches(rawPassword, encodedPassword);
    }

    public static void main(String[] args) {
        String password = "myPassword123";

        // Hash mật khẩu
        String hashedPassword = hashPassword(password);
        System.out.println("Hashed Password: " + hashedPassword);

        // Kiểm tra mật khẩu
        boolean matched = checkPassword("myPassword123", hashedPassword);
        System.out.println("Password Matched: " + matched);
    }
}
