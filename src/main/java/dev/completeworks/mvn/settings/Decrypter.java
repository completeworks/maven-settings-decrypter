package dev.completeworks.mvn.settings;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.concurrent.Callable;
import java.util.stream.Collectors;

import org.apache.maven.settings.Server;
import org.apache.maven.settings.Settings;
import org.apache.maven.settings.io.xpp3.SettingsXpp3Reader;
import org.codehaus.plexus.util.xml.pull.XmlPullParserException;
import org.sonatype.plexus.components.cipher.DefaultPlexusCipher;
import org.sonatype.plexus.components.cipher.PlexusCipherException;
import org.sonatype.plexus.components.sec.dispatcher.DefaultSecDispatcher;
import org.sonatype.plexus.components.sec.dispatcher.SecDispatcherException;
import org.sonatype.plexus.components.sec.dispatcher.SecUtil;
import org.sonatype.plexus.components.sec.dispatcher.model.SettingsSecurity;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

@Command(name = "mvn-settings-decrypter", mixinStandardHelpOptions = true, version = "1.0",
         description = "Decrypt the passwords stored in Maven settings.xml")
public class Decrypter implements Callable<Integer> {

    @Parameters(paramLabel = "SETTINGS-SECURITY", arity = "1", description = "The path to a settings-security.xml")
    private Path settingsSecurityXml;

    @Option(names = {"-s", "--settings"}, required = true, description = "The path to a settings.xml encrypted with the provided SETTINGS-SECURITY file")
    private Path settingsXml;
    
    public static void main(String... args) throws Exception {
        int exitCode = new CommandLine(new Decrypter()).execute(args);
        System.exit(exitCode);
    }

    public Integer call() throws Exception {
        if (!Files.exists(settingsSecurityXml)) {
            throw new FileNotFoundException(settingsSecurityXml.toAbsolutePath().toString());
        }
        if (!Files.exists(settingsXml)) {
            throw new FileNotFoundException(settingsXml.toAbsolutePath().toString());
        }

        StringBuilder sb = new StringBuilder("{");

        String masterPassword = decryptMasterPassword(settingsSecurityXml);
        sb.append(jsonObjectField("masterPassword", b64encode(masterPassword))).append(",");

        sb.append(quote("servers")).append(":[");

        String serversStr = readSettingsXml(settingsXml).getServers().stream()
            .map(server -> toJSONObject(server, masterPassword))
            .collect(Collectors.joining(","));
        sb.append(serversStr);

        sb.append("]}");

        System.out.println(sb.toString());
        return 0;
    }

    private static String toJSONObject(Server server, String masterPassword) {
        final String password;
        if (server.getPassword() != null) {
            password = decryptPassword(server.getPassword(), masterPassword);
        } else if (server.getPassphrase() != null) {
            password = decryptPassword(server.getPassphrase(), masterPassword);
        } else {
            password = "";
        }
        return new StringBuilder()
            .append("{")
            .append(jsonObjectField("id", server.getId())).append(",")
            .append(jsonObjectField("username", server.getUsername())).append(",")
            .append(jsonObjectField("password", b64encode(password)))
            .append("}")
            .toString();
    }

    private static String jsonObjectField(String name, String value) {
        StringBuilder sb = new StringBuilder();
        return sb
            .append(quote(name))
            .append(":")
            .append(quote(value))
            .toString();
    }

    private static String quote(String s) {
        return '"' + s + '"';
    }

    private static String b64encode(String s) {
        if (s == null) {
            return null;
        }
        return Base64.getEncoder().encodeToString(s.getBytes());
    }

    private static String decryptMasterPassword(Path settingsSecurityXml) throws PlexusCipherException, SecDispatcherException {
        SettingsSecurity settingsSecurity = SecUtil.read(settingsSecurityXml.toAbsolutePath().toString(), true);
        if (settingsSecurity.getMaster() != null) {
            return decryptPassword(settingsSecurity.getMaster(), DefaultSecDispatcher.SYSTEM_PROPERTY_SEC_LOCATION);
        }
        return null;
    }

    private static String decryptPassword(String encodedPassword, String key) {
        try {
            DefaultPlexusCipher cipher = new DefaultPlexusCipher();
            return cipher.decryptDecorated(encodedPassword, key);
        } catch (PlexusCipherException e) {
            throw new RuntimeException(e);
        }
    }

    private static Settings readSettingsXml(Path file) throws IOException, XmlPullParserException {
        try (InputStream is = Files.newInputStream(file)) {
            SettingsXpp3Reader reader = new SettingsXpp3Reader();
            return reader.read(is);
        }
    }
}
