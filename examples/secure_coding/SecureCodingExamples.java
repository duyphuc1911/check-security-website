import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.owasp.encoder.Encode;

/** secure coding examples */
public final class SecureCodingExamples {
    private SecureCodingExamples() {}

    /** sql injection */
    public static String findUserName(Connection connection, long userId)
            throws SQLException {
        String sql = "SELECT display_name FROM users WHERE id = ?";
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setLong(1, userId);
            try (ResultSet result = statement.executeQuery()) {
                return result.next() ? result.getString("display_name") : null;
            }
        }
    }

    /** xss */
    public static String renderSearchText(String userInput) {
        return Encode.forHtml(userInput);
    }

    /** os cmd injection */
    public static int runFixedGitStatus() throws IOException, InterruptedException {
        Process process = new ProcessBuilder(List.of("git", "status", "--short"))
                .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                .redirectError(ProcessBuilder.Redirect.DISCARD)
                .start();
        if (!process.waitFor(10, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            throw new IOException("git status timed out");
        }
        if (process.exitValue() != 0) {
            throw new IOException("git status failed");
        }
        return process.exitValue();
    }

    /** path traversal */
    public static byte[] readUpload(Path uploadRoot, String requestedName)
            throws IOException {
        Path root = uploadRoot.toRealPath();
        Path candidate = root.resolve(requestedName).toRealPath();
        if (!candidate.startsWith(root)) {
            throw new SecurityException("Requested file is outside the upload directory");
        }
        return Files.readAllBytes(candidate);
    }
}
