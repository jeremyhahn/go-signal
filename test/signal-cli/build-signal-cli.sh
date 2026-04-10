#!/bin/bash
set -euo pipefail

SERVER_URL="${SIGNAL_SERVER_URL:-https://signal-server:8080}"
SIGNAL_CLI_VERSION="${SIGNAL_CLI_VERSION:-v0.13.12}"
BUILD_DIR="/opt/signal-cli-build"
CA_CERT="/tmp/ca-cert.pem"

echo "Building signal-cli with custom server: ${SERVER_URL}"

# Clone
git clone --depth 1 --branch "${SIGNAL_CLI_VERSION}" https://github.com/AsamK/signal-cli.git "${BUILD_DIR}"
cd "${BUILD_DIR}"

# Patch LiveConfig.java - replace all hardcoded URLs
LIVE_CONFIG="lib/src/main/java/org/asamk/signal/manager/config/LiveConfig.java"
sed -i "s|https://chat.signal.org|${SERVER_URL}|g" "${LIVE_CONFIG}"
sed -i "s|https://cdn.signal.org|${SERVER_URL}/cdn|g" "${LIVE_CONFIG}"
sed -i "s|https://cdn2.signal.org|${SERVER_URL}/cdn2|g" "${LIVE_CONFIG}"
sed -i "s|https://cdn3.signal.org|${SERVER_URL}/cdn3|g" "${LIVE_CONFIG}"
sed -i "s|https://storage.signal.org|${SERVER_URL}/storage|g" "${LIVE_CONFIG}"
sed -i "s|https://cdsi.signal.org|${SERVER_URL}/cdsi|g" "${LIVE_CONFIG}"
sed -i "s|https://svr2.signal.org|${SERVER_URL}/svr2|g" "${LIVE_CONFIG}"

# Also patch StagingConfig.java for --service-environment staging
STAGING_CONFIG="lib/src/main/java/org/asamk/signal/manager/config/StagingConfig.java"
sed -i "s|https://chat.staging.signal.org|${SERVER_URL}|g" "${STAGING_CONFIG}"
sed -i "s|https://cdn-staging.signal.org|${SERVER_URL}/cdn|g" "${STAGING_CONFIG}"
sed -i "s|https://cdn2-staging.signal.org|${SERVER_URL}/cdn2|g" "${STAGING_CONFIG}"
sed -i "s|https://cdn3-staging.signal.org|${SERVER_URL}/cdn3|g" "${STAGING_CONFIG}"
sed -i "s|https://storage-staging.signal.org|${SERVER_URL}/storage|g" "${STAGING_CONFIG}"
sed -i "s|https://cdsi.staging.signal.org|${SERVER_URL}/cdsi|g" "${STAGING_CONFIG}"
sed -i "s|https://svr2.staging.signal.org|${SERVER_URL}/svr2|g" "${STAGING_CONFIG}"

# Create a TrustStore that embeds our test CA certificate directly in the source
# code and creates a BKS keystore containing it. This guarantees the CA cert is
# always available regardless of the runtime JRE's cacerts state.
# The CA cert PEM is read at build time and embedded as a Java string constant.

# Convert PEM to a Java string literal: wrap each line in quotes with \n
CA_PEM_JAVA=$(awk '{printf "        \"%s\\n\" +\n", $0}' /tmp/ca-cert.pem | sed '$ s/ +$//')
echo "Embedding CA cert PEM into TestTrustStore.java ($(wc -l < /tmp/ca-cert.pem) lines)"

cat > lib/src/main/java/org/asamk/signal/manager/config/TestTrustStore.java << JAVAEOF
package org.asamk.signal.manager.config;

import org.whispersystems.signalservice.api.push.TrustStore;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public class TestTrustStore implements TrustStore {
    private static final byte[] KEYSTORE_BYTES;

    // Embedded test CA certificate (injected at build time)
    private static final String CA_CERT_PEM =
${CA_PEM_JAVA};

    static {
        try {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

            // Parse the embedded CA certificate
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate caCert = (X509Certificate) cf.generateCertificate(
                new ByteArrayInputStream(CA_CERT_PEM.getBytes("UTF-8")));
            System.out.println("TestTrustStore: embedded CA cert subject: " + caCert.getSubjectX500Principal());

            // Create a BKS keystore with our CA cert
            KeyStore bksStore = KeyStore.getInstance("BKS", "BC");
            bksStore.load(null, null);
            bksStore.setCertificateEntry("signal-test-ca", caCert);

            // Also add standard JRE CAs for any other connections that need them
            try {
                String cacertsPath = System.getProperty("java.home") + "/lib/security/cacerts";
                KeyStore defaultKs = KeyStore.getInstance(KeyStore.getDefaultType());
                try (java.io.FileInputStream fis = new java.io.FileInputStream(cacertsPath)) {
                    defaultKs.load(fis, "changeit".toCharArray());
                }
                Enumeration<String> aliases = defaultKs.aliases();
                int count = 0;
                while (aliases.hasMoreElements()) {
                    String alias = aliases.nextElement();
                    if (defaultKs.isCertificateEntry(alias)) {
                        bksStore.setCertificateEntry(alias, defaultKs.getCertificate(alias));
                        count++;
                    }
                }
                System.out.println("TestTrustStore: also loaded " + count + " JRE CA certificates");
            } catch (Exception e) {
                System.out.println("TestTrustStore: WARNING: could not load JRE cacerts: " + e);
            }

            java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
            bksStore.store(baos, "signal-test".toCharArray());
            KEYSTORE_BYTES = baos.toByteArray();
            System.out.println("TestTrustStore: BKS keystore created (" + bksStore.size() + " entries, " + KEYSTORE_BYTES.length + " bytes)");
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize TestTrustStore", e);
        }
    }

    @Override
    public InputStream getKeyStoreInputStream() {
        return new ByteArrayInputStream(KEYSTORE_BYTES);
    }

    @Override
    public String getKeyStorePassword() {
        return "signal-test";
    }
}
JAVAEOF

# Patch the OkHttp client factory in signal-service-java to trust all certs.
# Find and patch the class that creates the OkHttpClient with custom SSL.
# In libsignal-service-java, this is typically in PushServiceSocket or a utility.
# We patch it by adding a startup hook that overrides SSL defaults.
#
# Instead of patching the compiled JAR, we add a Java agent-style initializer
# via signal-cli's main class. The signal-cli entry point is:
# org.asamk.signal.Main
MAIN_CLASS="src/main/java/org/asamk/signal/Main.java"

# Add trust-all SSL initialization at the very beginning of main()
# Find the main method and inject SSL bypass code after it
if grep -q "public static void main" "${MAIN_CLASS}"; then
    echo "Patching Main.java to disable SSL verification..."
    sed -i '/public static void main/,/^[[:space:]]*{/{
        /^[[:space:]]*{/a\
        // === TEST SSL BYPASS - Trust all certificates ===\
        try {\
            javax.net.ssl.TrustManager[] trustAll = new javax.net.ssl.TrustManager[]{\
                new javax.net.ssl.X509TrustManager() {\
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {\
                        return new java.security.cert.X509Certificate[0];\
                    }\
                    public void checkClientTrusted(java.security.cert.X509Certificate[] c, String t) {}\
                    public void checkServerTrusted(java.security.cert.X509Certificate[] c, String t) {}\
                }\
            };\
            javax.net.ssl.SSLContext sc = javax.net.ssl.SSLContext.getInstance("TLS");\
            sc.init(null, trustAll, new java.security.SecureRandom());\
            javax.net.ssl.SSLContext.setDefault(sc);\
            javax.net.ssl.HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());\
            javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier((h, s) -> true);\
        } catch (Exception e) {\
            System.err.println("WARNING: Failed to set up trust-all SSL: " + e);\
        }\
        // === END TEST SSL BYPASS ===
    }' "${MAIN_CLASS}"
fi

# Patch SendHelper to log full stack traces for send failures and fix the
# sendTypingMessage NPE when sealed sender access is null.
# List.of(null) throws NullPointerException; we use Optional to handle it.
SEND_HELPER=$(find lib -name "SendHelper.java" -path "*/helper/*" | head -1)
if [ -n "${SEND_HELPER}" ]; then
    echo "Patching SendHelper to log full exception stack traces..."
    sed -i 's/logger.debug("Exception", e);/logger.warn("Exception stack trace:", e);/g' "${SEND_HELPER}"

    echo "Patching SendHelper.sendTypingMessage to handle null sealed sender access..."
    # The original code does: List.of(unidentifiedAccess)
    # which throws NPE when unidentifiedAccess is null (no profile key for recipient).
    # Replace with: java.util.Collections.singletonList(unidentifiedAccess)
    # which safely wraps null values.
    sed -i 's/List\.of(unidentifiedAccess)/java.util.Collections.singletonList(unidentifiedAccess)/g' "${SEND_HELPER}"
fi

# Patch LiveConfig and StagingConfig to use TestTrustStore
echo "Patching LiveConfig to use TestTrustStore..."
sed -i 's/new WhisperTrustStore()/new TestTrustStore()/g' "${LIVE_CONFIG}"
sed -i 's/new LiveTrustStore()/new TestTrustStore()/g' "${LIVE_CONFIG}"
sed -i 's/new IasTrustStore()/new TestTrustStore()/g' "${LIVE_CONFIG}"
sed -i 's/new WhisperTrustStore()/new TestTrustStore()/g' "${STAGING_CONFIG}"
sed -i 's/new StagingTrustStore()/new TestTrustStore()/g' "${STAGING_CONFIG}"
sed -i 's/new LiveTrustStore()/new TestTrustStore()/g' "${STAGING_CONFIG}"
sed -i 's/new IasTrustStore()/new TestTrustStore()/g' "${STAGING_CONFIG}"

# Show patching results
echo "Trust store references in LiveConfig:"
grep -n "TrustStore" "${LIVE_CONFIG}" || true

# ===========================================================================
# Patch CDSI contact discovery to use REST API
# ===========================================================================
# Since we don't implement the full CDSI Noise+SGX WebSocket protocol,
# we patch signal-cli's RecipientHelper to resolve unknown numbers via
# a REST API call to /v1/directory/lookup instead of CDSI.
echo "Patching contact discovery to use REST API..."

RECIPIENT_HELPER=$(find lib -name "RecipientHelper.java" -path "*/helper/*" | head -1)
if [ -n "${RECIPIENT_HELPER}" ]; then
    echo "Found RecipientHelper: ${RECIPIENT_HELPER}"

    # Use Python to safely replace the getRegisteredUserByNumber method body.
    # This avoids fragile sed multi-line editing. The Python script:
    # 1. Finds the method by signature
    # 2. Counts braces to find the method boundary
    # 3. Inserts REST lookup code before the CDSI call
    python3 - "${RECIPIENT_HELPER}" "${SERVER_URL}" << 'PYEOF'
import sys, re

file_path = sys.argv[1]
server_url = sys.argv[2]

with open(file_path, 'r') as f:
    lines = f.readlines()

# Find the getRegisteredUserByNumber method
method_start = -1
for i, line in enumerate(lines):
    if 'private ServiceId getRegisteredUserByNumber(final String number)' in line:
        method_start = i
        break

if method_start < 0:
    # Try alternative signature
    for i, line in enumerate(lines):
        if 'getRegisteredUserByNumber' in line and 'private' in line:
            method_start = i
            break

if method_start < 0:
    print("WARNING: getRegisteredUserByNumber method not found, skipping CDSI patch")
    sys.exit(0)

# Find the opening brace of the method
brace_line = method_start
while brace_line < len(lines) and '{' not in lines[brace_line]:
    brace_line += 1

# Count braces to find the end of the method
depth = 0
method_end = brace_line
for i in range(brace_line, len(lines)):
    depth += lines[i].count('{') - lines[i].count('}')
    if depth == 0:
        method_end = i
        break

print(f"Found getRegisteredUserByNumber at lines {method_start+1}-{method_end+1}")

# Build the replacement method that tries REST before falling through to CDSI
rest_block = '''    private ServiceId getRegisteredUserByNumber(final String number) throws IOException, UnregisteredRecipientException {{
        // === PATCHED: Try REST directory lookup before CDSI ===
        try {{
            java.net.URL lookupUrl = new java.net.URL("{server_url}/v1/directory/lookup");
            java.net.HttpURLConnection lookupConn;
            if (lookupUrl.getProtocol().equals("https")) {{
                javax.net.ssl.HttpsURLConnection httpsConn = (javax.net.ssl.HttpsURLConnection) lookupUrl.openConnection();
                javax.net.ssl.SSLContext sslCtx = javax.net.ssl.SSLContext.getInstance("TLS");
                sslCtx.init(null, new javax.net.ssl.TrustManager[]{{new javax.net.ssl.X509TrustManager() {{
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {{ return new java.security.cert.X509Certificate[0]; }}
                    public void checkClientTrusted(java.security.cert.X509Certificate[] c, String t) {{}}
                    public void checkServerTrusted(java.security.cert.X509Certificate[] c, String t) {{}}
                }}}}, new java.security.SecureRandom());
                httpsConn.setSSLSocketFactory(sslCtx.getSocketFactory());
                httpsConn.setHostnameVerifier((hostname, session) -> true);
                lookupConn = httpsConn;
            }} else {{
                lookupConn = (java.net.HttpURLConnection) lookupUrl.openConnection();
            }}
            lookupConn.setRequestMethod("PUT");
            lookupConn.setRequestProperty("Content-Type", "application/json");
            lookupConn.setDoOutput(true);
            byte[] reqBody = ("{{\\"numbers\\":[\\"" + number + "\\"]}}").getBytes();
            try (java.io.OutputStream lookupOs = lookupConn.getOutputStream()) {{
                lookupOs.write(reqBody);
            }}
            if (lookupConn.getResponseCode() == 200) {{
                try (java.io.BufferedReader lookupReader = new java.io.BufferedReader(
                        new java.io.InputStreamReader(lookupConn.getInputStream()))) {{
                    StringBuilder lookupSb = new StringBuilder();
                    String lookupLine;
                    while ((lookupLine = lookupReader.readLine()) != null) lookupSb.append(lookupLine);
                    String lookupJson = lookupSb.toString();
                    // Simple JSON parse: find "uuid":"<value>"
                    int uuidFieldIdx = lookupJson.indexOf("\\"uuid\\":\\"");
                    if (uuidFieldIdx >= 0) {{
                        int uuidStart = uuidFieldIdx + 8; // skip past "uuid":"
                        int uuidEnd = lookupJson.indexOf("\\"", uuidStart);
                        String resolvedUuid = lookupJson.substring(uuidStart, uuidEnd);
                        logger.debug("REST directory lookup resolved {{}} -> {{}}", number, resolvedUuid);
                        return ACI.from(java.util.UUID.fromString(resolvedUuid));
                    }}
                }}
            }}
            logger.debug("REST directory lookup: no result for {{}}", number);
        }} catch (Exception restEx) {{
            logger.warn("REST directory lookup failed for {{}}: {{}}", number, restEx.getMessage());
        }}
        // === END REST PATCH ===
        // Fall through to original CDSI-based resolution
'''.format(server_url=server_url)

# Extract the original method body (everything between the opening and closing braces)
# Skip the method signature and opening brace, keep the body, skip the closing brace
original_body_lines = lines[brace_line + 1 : method_end]
original_body = ''.join(original_body_lines)

# Build the new method: REST block + original body + closing brace
new_method = rest_block + original_body + '    }\n'

# Replace the method
new_lines = lines[:method_start] + [new_method] + lines[method_end + 1:]

with open(file_path, 'w') as f:
    f.writelines(new_lines)

print("SUCCESS: Patched getRegisteredUserByNumber with REST lookup fallback")
PYEOF
    echo "RecipientHelper patching complete"
else
    echo "WARNING: RecipientHelper not found"
    find lib -path "*/helper/*.java" | head -20
fi

# ===========================================================================
# Patch SVR2 to be a no-op for setPin/removePin
# ===========================================================================
# Since we don't implement the SVR2 Noise protocol, we patch signal-cli to
# skip the SVR2 backup/restore operations. We replace the entire method
# bodies that call SVR2, keeping only the registration lock operations.
echo "Patching SVR2 PIN helper to skip SVR2 backup..."

PIN_HELPER=$(find lib -name "PinHelper.java" -path "*/helper/*" | head -1)
if [ -z "${PIN_HELPER}" ]; then
    PIN_HELPER=$(find lib -name "PinHelper.java" | head -1)
fi

if [ -n "${PIN_HELPER}" ]; then
    echo "Found PinHelper: ${PIN_HELPER}"

    # The PinHelper methods (setRegistrationLockPin, removeRegistrationLockPin) collect
    # IOException from SVR2 calls and throw it at the end with:
    #   if (exception != null) { throw exception; }
    # We simply replace "throw exception" with a log statement so the methods
    # return normally even when SVR2 fails.
    echo "Patching PinHelper to not throw on SVR2 failure..."
    sed -i 's/throw exception;/System.out.println("SVR2 operation skipped: " + exception.getMessage());/g' "${PIN_HELPER}"
    echo "PinHelper patched successfully"
    grep -n "SVR2 operation skipped\|throw exception" "${PIN_HELPER}" || true
else
    echo "WARNING: PinHelper not found"
    find lib -name "*.java" | xargs grep -l "SecureValueRecovery\|backupMasterKey" 2>/dev/null | head -10 || true
fi

# ===========================================================================
# Patch change number flow
# ===========================================================================
# Signal-cli's finishChangeNumber may call additional endpoints. Patch the
# ChangeNumberHelper to use simplified verification if possible.
echo "Checking change number implementation..."
CHANGE_NUMBER_HELPER=$(find lib -name "ChangeNumberHelper.java" -o -name "AccountHelper.java" | head -1)
if [ -n "${CHANGE_NUMBER_HELPER}" ]; then
    echo "Found: ${CHANGE_NUMBER_HELPER}"
    echo "=== Change number references ==="
    grep -n "changeNumber\|change_number\|v2/accounts/number\|v1/accounts/number" "${CHANGE_NUMBER_HELPER}" | head -10 || true
    echo "=== End change number references ==="
fi

# Also check PushServiceSocket for the change number URL
echo "=== PushServiceSocket change number URL ==="
find . -name "PushServiceSocket.java" -exec grep -n "changeNumber\|accounts/number" {} \; || true
echo "=== End PushServiceSocket analysis ==="

# Build
./gradlew installDist -x test

# Symlink to known location
ln -sf "${BUILD_DIR}/build/install/signal-cli" /opt/signal-cli

echo "signal-cli built successfully at /opt/signal-cli"
echo "Binary: /opt/signal-cli/bin/signal-cli"
