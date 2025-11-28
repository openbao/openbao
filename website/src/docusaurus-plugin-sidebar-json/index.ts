import type { LoadContext, Plugin } from "@docusaurus/types";
import * as path from "path";

export default function pluginSidebarJson(
    context: LoadContext,
    options: unknown,
): Plugin {
    return {
        name: "docusaurus-plugin-sidebar-json",
        extendCli(cli) {
            cli.command("sidebar:json <sidebarPath>")
                .description(
                    "Convert a sidebars.ts file to JSON and print to stdout",
                )
                .action((sidebarPath: string) => {
                    try {
                        const absolutePath = path.resolve(
                            context.siteDir,
                            sidebarPath,
                        );
                        const sidebarModule = require(absolutePath);
                        const sidebarContent =
                            sidebarModule.default || sidebarModule;
                        console.log(JSON.stringify(sidebarContent, null, 2));
                    } catch (error) {
                        console.error(
                            `Error processing sidebar file: ${(error as Error).message}`,
                        );
                        process.exit(1);
                    }
                });
        },
    };
}
