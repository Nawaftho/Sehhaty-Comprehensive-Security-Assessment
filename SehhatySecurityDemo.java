import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * Simple POC style Java code inspired by the Sehhaty security report
 * This is NOT production code It only demonstrates concepts
 */
public class SehhatySecurityDemo {

    public static void main(String[] args) {
        // Setup services
        CryptoService cryptoService = new CryptoService();
        AuditService auditService = new AuditService();
        InMemoryUserStore userStore = new InMemoryUserStore();
        InMemoryRecordStore recordStore = new InMemoryRecordStore(cryptoService);
        AuthService authService = new AuthService(userStore);
        HealthRecordService recordService = new HealthRecordService(recordStore, auditService);

        // Create demo data
        userStore.addUser("1234567890", "Password123", "PATIENT", "P001");
        userStore.addUser("DOC001", "DoctorPass", "DOCTOR", "D001");

        recordStore.saveRecord(new HealthRecord("R001", "P001",
                "Diabetes Type 2",
                "Needs regular follow up and diet control",
                cryptoService));

        try {
            // Patient login
            LoginRequest patientLogin = new LoginRequest("1234567890", "Password123");
            AuthResponse patientAuth = authService.login(patientLogin);
            System.out.println("Patient login token " + patientAuth.getAccessToken());

            // Doctor login
            LoginRequest doctorLogin = new LoginRequest("DOC001", "DoctorPass");
            AuthResponse doctorAuth = authService.login(doctorLogin);
            System.out.println("Doctor login token " + doctorAuth.getAccessToken());

            // Patient tries to view own record
            System.out.println("\nPatient accessing own record");
            HealthRecord result1 = recordService.getRecord(
                    patientAuth,
                    "P001" // patientId
            );
            System.out.println("Diagnosis " + result1.getDiagnosisDecrypted());
            System.out.println("Notes " + result1.getNotesDecrypted());

            // Patient tries to view someone else record
            System.out.println("\nPatient accessing another record");
            try {
                recordService.getRecord(patientAuth, "OTHER_PATIENT");
            } catch (SecurityException e) {
                System.out.println("Access denied for patient " + e.getMessage());
            }

            // Doctor viewing patient record
            System.out.println("\nDoctor accessing patient record");
            HealthRecord result2 = recordService.getRecord(
                    doctorAuth,
                    "P001"
            );
            System.out.println("Diagnosis " + result2.getDiagnosisDecrypted());
            System.out.println("Notes " + result2.getNotesDecrypted());

        } catch (Exception ex) {
            GlobalExceptionHandler.handle(ex);
        }
    }
}

/**
 * Simple DTO for login request
 */
class LoginRequest {
    private String nationalIdOrUsername;
    private String password;

    public LoginRequest(String nationalIdOrUsername, String password) {
        this.nationalIdOrUsername = nationalIdOrUsername;
        this.password = password;
    }

    public String getNationalIdOrUsername() {
        return nationalIdOrUsername;
    }

    public String getPassword() {
        return password;
    }
}

/**
 * Simple DTO for auth response
 */
class AuthResponse {
    private String accessToken;
    private String role;
    private String subjectId; // patientId or doctorId

    public AuthResponse(String accessToken, String role, String subjectId) {
        this.accessToken = accessToken;
        this.role = role;
        this.subjectId = subjectId;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public String getRole() {
        return role;
    }

    public String getSubjectId() {
        return subjectId;
    }
}

/**
 * Very simple in memory user store
 */
class InMemoryUserStore {
    static class User {
        String username;
        String passwordHash;
        String role;
        String subjectId;

        User(String username, String passwordHash, String role, String subjectId) {
            this.username = username;
            this.passwordHash = passwordHash;
            this.role = role;
            this.subjectId = subjectId;
        }
    }

    private Map<String, User> users = new HashMap<>();

    public void addUser(String username, String rawPassword, String role, String subjectId) {
        String hashed = PasswordHasher.hash(rawPassword);
        users.put(username, new User(username, hashed, role, subjectId));
    }

    public User findByUsername(String username) {
        return users.get(username);
    }
}

/**
 * Simple auth service with basic validation
 */
class AuthService {

    private final InMemoryUserStore userStore;

    public AuthService(InMemoryUserStore userStore) {
        this.userStore = userStore;
    }

    public AuthResponse login(LoginRequest request) {
        validateLoginRequest(request);

        InMemoryUserStore.User user = userStore.findByUsername(request.getNationalIdOrUsername());
        if (user == null) {
            throw new SecurityException("Invalid credentials");
        }

        if (!PasswordHasher.verify(request.getPassword(), user.passwordHash)) {
            throw new SecurityException("Invalid credentials");
        }

        String token = TokenGenerator.generateToken(user.username, user.role);

        return new AuthResponse(token, user.role, user.subjectId);
    }

    private void validateLoginRequest(LoginRequest request) {
        if (request.getNationalIdOrUsername() == null || request.getNationalIdOrUsername().isBlank()) {
            throw new IllegalArgumentException("Username is required");
        }
        if (request.getPassword() == null || request.getPassword().isBlank()) {
            throw new IllegalArgumentException("Password is required");
        }
    }
}

/**
 * Simple health record entity with pseudo encryption
 */
class HealthRecord {
    private String id;
    private String patientId;
    private String diagnosisEncrypted;
    private String notesEncrypted;
    private CryptoService cryptoService;

    public HealthRecord(String id, String patientId, String diagnosisPlain, String notesPlain, CryptoService cryptoService) {
        this.id = id;
        this.patientId = patientId;
        this.cryptoService = cryptoService;
        this.diagnosisEncrypted = cryptoService.encrypt(diagnosisPlain);
        this.notesEncrypted = cryptoService.encrypt(notesPlain);
    }

    public String getId() {
        return id;
    }

    public String getPatientId() {
        return patientId;
    }

    public String getDiagnosisDecrypted() {
        return cryptoService.decrypt(diagnosisEncrypted);
    }

    public String getNotesDecrypted() {
        return cryptoService.decrypt(notesEncrypted);
    }
}

/**
 * Simple in memory store for records
 */
class InMemoryRecordStore {
    private Map<String, HealthRecord> recordsByPatient = new HashMap<>();

    public InMemoryRecordStore(CryptoService cryptoService) {
        // empty
    }

    public void saveRecord(HealthRecord record) {
        recordsByPatient.put(record.getPatientId(), record);
    }

    public HealthRecord findByPatientId(String patientId) {
        return recordsByPatient.get(patientId);
    }
}

/**
 * Service to access records with simple RBAC logic
 */
class HealthRecordService {

    private final InMemoryRecordStore recordStore;
    private final AuditService auditService;

    public HealthRecordService(InMemoryRecordStore recordStore, AuditService auditService) {
        this.recordStore = recordStore;
        this.auditService = auditService;
    }

    public HealthRecord getRecord(AuthResponse auth, String requestedPatientId) {
        if (auth == null) {
            throw new SecurityException("Not authenticated");
        }

        boolean allowed = false;

        if ("PATIENT".equals(auth.getRole()) && requestedPatientId.equals(auth.getSubjectId())) {
            allowed = true;
        }

        if ("DOCTOR".equals(auth.getRole())) {
            // In real system check doctor patient assignment
            allowed = true;
        }

        if (!allowed) {
            throw new SecurityException("Access denied");
        }

        HealthRecord record = recordStore.findByPatientId(requestedPatientId);
        if (record == null) {
            throw new IllegalArgumentException("Record not found");
        }

        auditService.logRecordAccess(auth.getSubjectId(), requestedPatientId, auth.getRole());
        return record;
    }
}

/**
 * Very simple crypto service using Base64 as placeholder
 * In real life use AES GCM and proper key management
 */
class CryptoService {

    public String encrypt(String plainText) {
        if (plainText == null) return null;
        return Base64.getEncoder().encodeToString(plainText.getBytes(StandardCharsets.UTF_8));
    }

    public String decrypt(String cipherText) {
        if (cipherText == null) return null;
        byte[] decoded = Base64.getDecoder().decode(cipherText);
        return new String(decoded, StandardCharsets.UTF_8);
    }
}

/**
 * Simple password hasher POC only not secure
 */
class PasswordHasher {

    public static String hash(String password) {
        if (password == null) return null;
        String reversed = new StringBuilder(password).reverse().toString();
        return Base64.getEncoder().encodeToString(reversed.getBytes(StandardCharsets.UTF_8));
    }

    public static boolean verify(String rawPassword, String storedHash) {
        String hashedRaw = hash(rawPassword);
        return hashedRaw != null && hashedRaw.equals(storedHash);
    }
}

/**
 * Simple token generator POC only
 */
class TokenGenerator {

    public static String generateToken(String username, String role) {
        String payload = username + "|" + role + "|" + System.currentTimeMillis();
        return Base64.getEncoder().encodeToString(payload.getBytes(StandardCharsets.UTF_8));
    }
}

/**
 * Simple audit logger to console
 */
class AuditService {

    public void logRecordAccess(String requesterId, String patientId, String role) {
        System.out.println("AUDIT record access requester " + requesterId
                + " role " + role
                + " patient " + patientId);
    }
}

/**
 * Global exception handler simulation
 */
class GlobalExceptionHandler {

    public static void handle(Exception ex) {
        System.err.println("Error " + ex.getClass().getSimpleName() + " " + ex.getMessage());
        // Stack trace could be logged internally here
    }
}
