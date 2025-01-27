
# OSINT Recon Tool

A Rust-based tool for performing OSINT (Open Source Intelligence) reconnaissance on domains, IPs, and emails, with the ability to analyze results using AI.

## Features
- **WHOIS Lookup**: Retrieve domain registration details.
- **Shodan API Queries**: Gather information on hosts and their vulnerabilities.
- **Have I Been Pwned (HIBP) Checks**: Check if an email has been compromised in a known data breach.
- **ChatGPT-Powered Analysis**: Analyze OSINT data with AI assistance for deeper insights.

## Requirements
- **Rust**: The tool is built using Rust, so you'll need to install it.
- **API Keys**: 
  - **OpenAI API Key**: Required for using the ChatGPT-powered analysis.
  - **Shodan API Key**: Required for querying the Shodan service.
  - Optionally, you can use the **Have I Been Pwned API** for email breach checks.
- **.env File**: Store your API keys securely in an `.env` file.

## Installation
### 1. Clone this repository:
```bash
git clone https://github.com/yourusername/osint-recon-tool.git
```

### 2. Install Rust (if not already installed):
Follow the instructions on [Rust's official website](https://www.rust-lang.org/tools/install) to install Rust.

### 3. Set up a `.env` file:
Create a `.env` file in the root of the project and add your API keys:
```dotenv
OPENAI_API_KEY=your_openai_api_key_here
SHODAN_API_KEY=your_shodan_api_key_here
```

### 4. Build the project:
```bash
cargo build --release
```

## Usage
You can run the tool using the following command:

```bash
cargo run -- <target> <type>
```

Where:
- `<target>` is the domain/IP/email you want to analyze.
- `<type>` is one of the following:
  - `whois`: Perform a WHOIS lookup on the target.
  - `shodan`: Query Shodan for host details.
  - `hibp`: Check if an email has been breached using Have I Been Pwned.

### Example Usage:
1. **WHOIS Lookup**:
   ```bash
   cargo run -- example.com whois
   ```

2. **Shodan Query**:
   ```bash
   cargo run -- 192.168.1.1 shodan
   ```

3. **HIBP Check**:
   ```bash
   cargo run -- example@example.com hibp
   ```

## Output
- The tool will print the raw OSINT data to the console.
- It will also save the data to a `.json` report file named `<target>_osint_report.json`.
- The OSINT data will be sent to OpenAI’s ChatGPT for analysis, and the results will be printed.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing
1. Fork the repository.
2. Create a new branch (`git checkout -b feature-branch`).
3. Commit your changes (`git commit -am 'Add new feature'`).
4. Push to the branch (`git push origin feature-branch`).
5. Open a pull request.

## Acknowledgments
- [Shodan](https://www.shodan.io/)
- [Have I Been Pwned](https://haveibeenpwned.com/)
- [OpenAI](https://openai.com/)
