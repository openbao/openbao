import CodeBlockWrap from "@site/src/components/CodeBlockWrap";
import BrowserOnly from "@docusaurus/BrowserOnly";
import Heading from "@theme/Heading";
import { useState, useEffect } from "react";

interface RpmRepoProps { gpgKeyName: string; }

const RpmRepo: React.FC<RpmRepoProps> = ({ gpgKeyName }) => (
    <>
        <Heading as="h4">Installation via official Package Repository</Heading>
        Simply add this repository configuration to your YUM-repos. YUM then verifies that the packages have been created and signed by the official pipeline and have not been tampered with.
        <BrowserOnly>
            {() => {
                const CodeBlock = require("@theme/CodeBlock").default;
                return (
                    <CodeBlock
                        language="shell"
                        title="/etc/yum.repos.d/openbao.repo"
                        showLineNumbers
                    >
                        {`[openbao]
name=openbao
baseurl=https://pkgs.openbao.org/rpm/$basearch
repo_gpgcheck=0
gpgcheck=1
enabled=1
gpgkey=https://openbao.org/assets/${gpgKeyName}
sslverify=1
sslcacert=/etc/pki/tls/certs/ca-bundle.crt
metadata_expire=300`}
                    </CodeBlock>
                );
            }}
        </BrowserOnly>
        <Heading as="h4">Install OpenBao</Heading>
        <BrowserOnly>
            {() => {
                const CodeBlock = require("@theme/CodeBlock").default;
                return (
                    <CodeBlock language="shell">sudo yum install -y openbao</CodeBlock>
                );
            }}
        </BrowserOnly>
    </>
);

export default RpmRepo;
