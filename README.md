# Take Back the Fediverse

> Take Back the Fediverse by decentralise the fediverse

It is essential to reclaim the Fediverse from centralised instances that disregard the fundamental principles of decentralisation in favour of the interests of large tech corporations. The decentralisation of the Fediverse is crucial for preserving freedom, democracy, and the human right to privacy.

Centralised platforms often prioritise profit over user rights, leading to the exploitation of personal data and the erosion of privacy. By decentralising the Fediverse, we empower individuals and communities to take control of their online presence, ensuring that their voices are heard without the interference of corporate agendas. 

Decentralisation fosters a more democratic internet, where users can engage freely and securely, without the fear of surveillance or censorship. It is a vital step towards creating a digital landscape that respects and upholds the rights of all individuals, promoting a more equitable and just society.

Let us unite to protect the values of the Fediverse and ensure that it remains a space for genuine connection, creativity, and freedom.

## Domain Analysis and CIDR Fetching

![Screenshot of domain_analyzer.py](https://github.com/user-attachments/assets/96716029-4230-4b52-944f-301a4005bb6f)

### Overview

This project aims to contribute to the decentralisation of the Fediverse by exposing servers that are hosted and centralised by unethical corporations, which have no intention of safeguarding your right to privacy. The primary function of this script is to analyse a list of domains to identify those hosted on major tech platforms, including Amazon, Cloudflare, Google, and Microsoft.

### Features

- Fetches IP/CIDR ranges for major tech platforms.
- Resolves domains to IP addresses and checks if they fall within the fetched ranges.
- Utilises asynchronous programming for efficient operation.
- Provides detailed output to the command line interface (CLI).
- Caches data until the end of the script execution to optimise memory usage.

### Installation

To run this project, ensure you have Python 3.12 installed in a Miniconda environment. You may also need to install the required dependencies.

```bash
conda create -n domain_analysis python=3.12 && \
    conda activate domain_analysis && \
    pip install -r requirements.txt
```
  
Or simply run `./setup_conda.sh` :)

### Usage

You can run the script using the following command:

```bash
python domain_analysis.py [options]
```

Arguments

    -i, --input: Specify the input file containing domains (default: instance.txt).
    -o, --output: Specify the output file to write filtered domains (default: filtered_domains.txt).
    -s, --socks5: Provide the SOCKS5 proxy address (e.g., socks5://127.0.0.1:9050).
    -d, --dns: Specify the DNS resolver to use (default: 192.168.56.3).
    -v, --version: Display the version of the script.
        --description: Show a description of the script's functionality.

### Example

```bash
python domain_analysis.py -i my_domains.txt -o filtered_results.txt -s socks5://127.0.0.1:9050
```

## License

This project is licensed under the AGPLv3. Copyright © spirillen.

## Contributing

Contributions are welcome! Please feel free to submit a pull request or open an issue for any suggestions or improvements.
