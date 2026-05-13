import BrowserOnly from "@docusaurus/BrowserOnly";
import Heading from "@theme/Heading";
import React, { Suspense, lazy, useEffect, useState } from "react";

const CodeBlock = lazy(() => import("@theme/CodeBlock"));

const DebRepo = ({ gpgKeyName }: { gpgKeyName: string }) => {
    const [gpgKey, setGPGKey] = useState("");

    useEffect(() => {
        fetch("/assets/" + gpgKeyName)
            .then((r) => r.text())
            .then((data) => setGPGKey(data.replace("\n\n", "\n.\n")))
            .catch(console.error);
    }, [gpgKeyName]);

    const repoFileContent = `Types: deb
URIs: https://pkgs.openbao.org/deb/
Suites: stable
Components: main
Signed-By:
${gpgKey.replaceAll(/^(?!$)/gm, " ")}`;

    return (
        <>
            <Heading as="h4">
                Installation via official Package Repository
            </Heading>

            Simply add this repository configuration to your DEB-sources.
            APT then verifies that the packages have been created and signed
            by the official pipeline and have not been tampered with.

            <BrowserOnly fallback={<pre>{repoFileContent}</pre>}>
                {() => (
                    <Suspense fallback={<pre>{repoFileContent}</pre>}>
                        <CodeBlock
                            language="shell"
                            title="/etc/apt/sources.list.d/openbao.sources"
                            showLineNumbers
                        >
                            {repoFileContent}
                        </CodeBlock>
                    </Suspense>
                )}
            </BrowserOnly>

            <Heading as="h4">Install OpenBao</Heading>

            <BrowserOnly
                fallback={
                    <pre>
                        sudo apt update && sudo apt install openbao
                    </pre>
                }
            >
                {() => (
                    <Suspense
                        fallback={
                            <pre>
                                sudo apt update && sudo apt install
                                openbao
                            </pre>
                        }
                    >
                        <CodeBlock language="shell">
                            sudo apt update && sudo apt install openbao
                        </CodeBlock>
                    </Suspense>
                )}
            </BrowserOnly>
        </>
    );
};

export default DebRepo;
