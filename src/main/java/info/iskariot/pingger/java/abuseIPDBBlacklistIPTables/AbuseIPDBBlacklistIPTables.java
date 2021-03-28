package info.iskariot.pingger.java.abuseIPDBBlacklistIPTables;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.URL;
import java.util.Arrays;
import java.util.List;

import javax.net.ssl.HttpsURLConnection;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class AbuseIPDBBlacklistIPTables
{
	/** The action for -j parameter of iptables */
	public static final String	ACTION				= "DROP";
	public static final String	ACTION_CHAIN		= "abuseipdb-blacklist-action";
	public static String		apiKey				= null;
	public static final String	CHAIN				= "abuseipdb-blacklist";
	public static String		inputJson			= null;
	public static String		jsonOutputFolder	= "./";

	public static void blacklistIP(String ip) throws IOException, InterruptedException
	{
		if (ip.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) {
			System.out.print("Blacklisting: " + ip + " # ");
			System.out.println(runCommand("iptables -A " + CHAIN + " -s " + ip + " -j " + ACTION_CHAIN));
		}
		else {
			System.err.println("ERROR: Not a supported IP-Address: " + ip);
		}
	}

	public static byte[] getBlacklist() throws FileNotFoundException, IOException
	{
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		try (InputStream is = inputJson == null ? getBlacklistStream() : new FileInputStream(new File(inputJson))) {
			byte[] buf = new byte[8192];
			int read = 0;
			do {
				baos.write(buf, 0, read);
				read = is.read(buf);
			}
			while (read >= 0);
		}
		if (inputJson == null) {
			try (PrintStream ps = new PrintStream(new File(jsonOutputFolder + "blacklist_" + System.currentTimeMillis() + ".json"))) {
				ps.write(baos.toByteArray());
				ps.flush();
			}
		}
		return baos.toByteArray();
	}

	public static InputStream getBlacklistStream() throws IOException
	{
		System.out.println("Downloading Blacklist from AbuseIPDB . . .");
		HttpsURLConnection con = (HttpsURLConnection) new URL("https://api.abuseipdb.com/api/v2/blacklist").openConnection();
		con.setRequestMethod("GET");
		con.setRequestProperty("Key", apiKey);
		con.connect();
		return con.getInputStream();
	}

	public static void main(String[] args) throws JsonParseException, IOException, InterruptedException
	{
		parseArgs(args);
		ObjectMapper mapper = new ObjectMapper();
		JsonFactory f = mapper.getFactory();
		byte[] json = getBlacklist();
		JsonParser jp = f.createParser(json);
		System.out.println("Parsing Blacklist");
		JsonNode rootNode = jp.readValueAsTree();
		System.out.println("Blacklist Timestamp: " + rootNode.get("meta").get("generatedAt").asText());
		JsonNode data = rootNode.get("data");
		prepareChains();
		if (data.isArray()) {
			for (JsonNode elem : data) {
				blacklistIP(elem.get("ipAddress").asText());
			}
		}

		Runtime.getRuntime().exec("iptables -A " + CHAIN + " -j RETURN");
		jp.close();
	}

	public static void prepareChains() throws IOException, InterruptedException
	{
		System.out.print("Clearing Blacklist . . . ");
		System.out.print(runCommand("iptables -F " + CHAIN) + ", ");
		System.out.print(runCommand("iptables -D INPUT -j " + CHAIN) + ", ");
		System.out.print(runCommand("iptables -D FORWARD -j " + CHAIN));
		System.out.println();
		if (runCommand("iptables -n -L " + ACTION_CHAIN, Arrays.asList(0, 1)) > 0) {
			System.out.print("Creating Blacklist-Action . . . ");
			System.out.print(runCommand("iptables -N " + ACTION_CHAIN) + ", ");
			Thread.sleep(250);
			System.out
					.print(
							runCommand("iptables", "-A", ACTION_CHAIN, "-j", "LOG", "--log-prefix", "ABUSEIPDB-BLACKLIST: ", "--log-level", "6")
									+ ", "
					);
			Thread.sleep(250);
			System.out.print(runCommand("iptables -A " + ACTION_CHAIN + " -j " + ACTION));
			System.out.println();
		}
		if (runCommand("iptables -n -L " + CHAIN) > 0) {
			System.out.print("Creating Blacklist . . . ");
			System.out.print(runCommand("iptables -N " + CHAIN));
			System.out.println();
		}
		System.out.print("Registering Blacklist . . . ");
		System.out.print(runCommand("iptables -I INPUT -j " + CHAIN) + ", ");
		System.out.print(runCommand("iptables -I FORWARD -j " + CHAIN));
		Thread.sleep(2000);
	}

	private static void parseArgs(String[] args)
	{
		for (int i = 0; i < args.length; i++) {
			switch (args[i].toLowerCase())
			{
				default:
					System.err.println("Unknown Argument: " + i + " => " + args[i]);
				case "-o":
				case "--output":
				case "--blackliststorage":
					jsonOutputFolder = args[++i];
					if (jsonOutputFolder.trim().isEmpty()) {
						jsonOutputFolder = "./";
					}
					if (!jsonOutputFolder.endsWith("/")) {
						jsonOutputFolder += "/";
					}
					break;

				case "-i":
				case "--input":
				case "--blacklist":
					inputJson = args[++i];
					if (inputJson.trim().isEmpty()) {
						inputJson = null;
					}
					break;

				case "-a":
				case "--key":
				case "--apikey":
					apiKey = args[++i];
					break;

				case "-h":
				case "-?":
				case "--help":
					System.out.println("Usage:");
					System.out.println("  -?, -h,       --help                         \tThis Help-Message");
					System.out.println("  -a, --key,    --apikey <api-key>             \tThe API-Key to use to download from the API");
					System.out
							.println(
									"  -i, --input,  --blacklist <json-file>        \tThe json file to read instead of downloading from the API"
							);
					System.out.println("  -o, --output, --blackliststorage <directory> \tThe directory to write the downloaded json files to");
					System.exit(0);
			}
		}
		if (apiKey == null && inputJson == null) {
			System.err.println("At least on needs to be specified: apikey/blacklist");
			System.err.println("See help");
			System.exit(1);
		}
	}

	private static int runCommand(List<Integer> ok, String... command) throws IOException, InterruptedException
	{
		Process p = Runtime.getRuntime().exec(command);
		try (
				BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
				BufferedReader err = new BufferedReader(new InputStreamReader(p.getErrorStream()))
		)
		{
			int exit = p.waitFor();
			if (!ok.contains(exit)) {
				System.out.println();
				System.out.println("Command: " + Arrays.toString(command));
				System.out.println("Failed with: " + exit);
				while (br.ready()) {
					System.out.println("[SubProcess] " + br.readLine());
				}
				int b = br.read();
				if (b >= 0) {
					System.out.print("[SubProcess] ");
				}
				while (b >= 0) {
					System.out.write(b);
					b = br.read();
				}
				System.out.println();
				while (err.ready()) {
					System.out.println("[SubProcess-Err] " + err.readLine());
				}
				b = err.read();
				if (b >= 0) {
					System.out.print("[SubProcess-Err] ");
				}
				while (b >= 0) {
					System.out.write(b);
					b = err.read();
				}
				System.out.println();
			}
			return exit;
		}
	}

	private static int runCommand(String command) throws IOException, InterruptedException
	{
		return runCommand(command, Arrays.asList(0));
	}

	private static int runCommand(String... command) throws IOException, InterruptedException
	{
		return runCommand(Arrays.asList(0), command);
	}

	private static int runCommand(String command, List<Integer> ok) throws IOException, InterruptedException
	{
		Process p = Runtime.getRuntime().exec(command);
		try (
				BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
				BufferedReader err = new BufferedReader(new InputStreamReader(p.getErrorStream()))
		)
		{
			int exit = p.waitFor();
			if (!ok.contains(exit)) {
				System.out.println();
				System.out.println("Command: " + command);
				System.out.println("Failed with: " + exit);
				while (br.ready()) {
					System.out.println("[SubProcess] " + br.readLine());
				}
				int b = br.read();
				if (b >= 0) {
					System.out.print("[SubProcess] ");
				}
				while (b >= 0) {
					System.out.write(b);
					b = br.read();
				}
				System.out.println();
				while (err.ready()) {
					System.out.println("[SubProcess-Err] " + err.readLine());
				}
				b = err.read();
				if (b >= 0) {
					System.out.print("[SubProcess-Err] ");
				}
				while (b >= 0) {
					System.out.write(b);
					b = err.read();
				}
				System.out.println();
			}
			return exit;
		}
	}
}
