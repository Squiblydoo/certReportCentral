# CertReportCentral

**This tool complements CertReport. CertReport generates a report locally for user submission. CertReportCentral reports the certificate to a public database.**

This tool is intended to reduce the load of effort required to report authenticode certificates. It is intended to take the smallest amount of effort from the reporter, but provide the certificate authority with most the information they need to make a decision. Once submitted, your report will be processed and the status will be viewable on the website: certcentral.org

To use the API, an API key is required. The API key is generated for you the first time you log in and is visible on the profile.

## Installing
Use pip! `pip install certReportCentral` or `pip3 install certReportCentral`

## Usage

**Note: In version 2, it is required to provide the `--hash` (or `-#`) switch**
 Here is an example:
Calling the script and passing in a SHA256 like this:<br>
`certReport --hash 89dc50024836f9ad406504a3b7445d284e97ec5dafdd8f2741f496cac84ccda9`

Once ran, it will parse and submit the information to certCentral and will be processed.

## Using VirusTotal
In version 2, it became possible to query VirusTotal. To use VirusTotal first set up your API key using the appropriate method for your operating system:
```
        On Linux:
        echo "export VT_API_KEY=your_api_key_here" >> ~/.bashrc
        source ~/.bashrc

        On Windows:
        setx VT_API_KEY "your_api_key"

        On MacOS:
        echo "export VT_API_KEY=your_api_key_here" >> ~/.zprofile
        source ~/.zprofile
```

Once the API key is configured as an environment variable the following command will generate a report:
```
certReport --hash 89dc50024836f9ad406504a3b7445d284e97ec5dafdd8f2741f496cac84ccda9 --service virustotal
```

Alternatively, the switches can be simplified:

```
certReport -# 89dc50024836f9ad406504a3b7445d284e97ec5dafdd8f2741f496cac84ccda9 -s VT
```

## Contributing
Please feel free to suggest changes to the script for additional certificate provider email addresses or methods of reporting. Half of the battle in reporting is finding where certificates should be submitted.

# Why Report?
Starting in 2018, the majority of certificates were no longer stolen, but they are issued to impostors (this case is argued in a scholarly article here: http://users.umiacs.umd.edu/~tdumitra/papers/WEIS-2018.pdf). I call these "Impostor Certs". 
In 2023, I published my research into 50 certificates used by one actor. My findings confirmed that certificates are used to sign multiple malware families: https://squiblydoo.blog/2023/05/12/certified-bad/.
In 2024, I published an article on Impostor certs, after having revoked 100 certificates used to sign the same malware, that article can be read here: https://squiblydoo.blog/2024/05/13/impostor-certs/.

The TLDR is that multiple actors use the same certificate and reporting a certificate raises the cost of signing for all threat actors and it can impact multiple malware campaigns.
