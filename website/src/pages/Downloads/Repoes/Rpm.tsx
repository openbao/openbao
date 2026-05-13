import BrowserOnly from "@docusaurus/BrowserOnly";
import Heading from "@theme/Heading";
import React, { FC, Suspense, lazy } from "react";

const CodeBlock = lazy(() => import("@theme/CodeBlock"));

interface RpmRepoProps {
    gpgKeyName: string;
}

const RpmRepo: FC<RpmRepoProps> = ({ gpgKeyName }) => {
    const repoContent = `[openbao]
name=openbao
baseurl=https://pkgs.openbao.org/rpm/$basearch
repo_gpgcheck=0
gpgcheck=1
enabled=1
gpgkey=https://openbao.org/assets/${gpgKeyName}
sslverify=1
sslcacert=/etc/pki/tls/certs/ca-bundle.crt
metadata_expire=300`;

    return (
        <>
            <Heading as="h4">
                Installation via official Package Repository
            </Heading>

            Simply add this repository configuration to your YUM-repos.
            YUM then verifies that the packages have been created and signed
            by the official pipeline and have not been tampered with.

            <BrowserOnly fallback={<pre>{repoContent}</pre>}>
                {() => (
                    <Suspense fallback={<pre>{repoContent}</pre>}>
                        <CodeBlock
                            language="shell"
                            title="/etc/yum.repos.d/openbao.repo"
                            showLineNumbers
                        >
                            {repoContent}
                        </CodeBlock>
                    </Suspense>
                )}
            </BrowserOnly>

            <Heading as="h4">Install OpenBao</Heading>

            <BrowserOnly
                fallback={<pre>sudo yum install -y openbao</pre>}
            >
                {() => (
                    <Suspense
                        fallback={
                            <pre>sudo yum install -y openbao</pre>
                        }
                    >
                        <CodeBlock language="shell">
                            sudo yum install -y openbao
                        </CodeBlock>
                    </Suspense>
                )}
            </BrowserOnly>
        </>
    );
};

export default RpmRepo;
