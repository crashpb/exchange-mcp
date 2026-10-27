# Third-party dependencies

This source release restores dependencies from nuget.org using the committed lockfiles. Package declarations below are an inventory, not a relicensing of third-party code. No NuGet binaries, Exchange schemas or container images are included.

| Package | Version | Declared license |
| --- | --- | --- |
| [Microsoft.AspNetCore.Authentication.JwtBearer](https://www.nuget.org/packages/Microsoft.AspNetCore.Authentication.JwtBearer/10.0.12) | 10.0.12 | MIT |
| [Microsoft.AspNetCore.TestHost](https://www.nuget.org/packages/Microsoft.AspNetCore.TestHost/10.0.12) | 10.0.12 | MIT |
| [Microsoft.Bcl.Cryptography](https://www.nuget.org/packages/Microsoft.Bcl.Cryptography/10.0.2) | 10.0.2 | MIT |
| [Microsoft.Extensions.AI.Abstractions](https://www.nuget.org/packages/Microsoft.Extensions.AI.Abstractions/10.8.3) | 10.8.3 | MIT |
| [Microsoft.IdentityModel.Abstractions](https://www.nuget.org/packages/Microsoft.IdentityModel.Abstractions/8.19.2) | 8.19.2 | MIT |
| [Microsoft.IdentityModel.JsonWebTokens](https://www.nuget.org/packages/Microsoft.IdentityModel.JsonWebTokens/8.19.2) | 8.19.2 | MIT |
| [Microsoft.IdentityModel.Logging](https://www.nuget.org/packages/Microsoft.IdentityModel.Logging/8.19.2) | 8.19.2 | MIT |
| [Microsoft.IdentityModel.Protocols](https://www.nuget.org/packages/Microsoft.IdentityModel.Protocols/8.19.2) | 8.19.2 | MIT |
| [Microsoft.IdentityModel.Protocols.OpenIdConnect](https://www.nuget.org/packages/Microsoft.IdentityModel.Protocols.OpenIdConnect/8.19.2) | 8.19.2 | MIT |
| [Microsoft.IdentityModel.Tokens](https://www.nuget.org/packages/Microsoft.IdentityModel.Tokens/8.19.2) | 8.19.2 | MIT |
| [ModelContextProtocol](https://www.nuget.org/packages/ModelContextProtocol/2.2.0) | 2.2.0 | Apache-2.0 |
| [ModelContextProtocol.AspNetCore](https://www.nuget.org/packages/ModelContextProtocol.AspNetCore/2.2.0) | 2.2.0 | Apache-2.0 |
| [ModelContextProtocol.Core](https://www.nuget.org/packages/ModelContextProtocol.Core/2.2.0) | 2.2.0 | Apache-2.0 |
| [System.DirectoryServices.Protocols](https://www.nuget.org/packages/System.DirectoryServices.Protocols/10.0.12) | 10.0.12 | MIT |
| [System.IdentityModel.Tokens.Jwt](https://www.nuget.org/packages/System.IdentityModel.Tokens.Jwt/8.19.2) | 8.19.2 | MIT |


The Model Context Protocol SDK 2.2.0 license includes its Apache-2.0 transition and historical MIT notice. Its full upstream text is retained in [licenses/modelcontextprotocol-LICENSE](licenses/modelcontextprotocol-LICENSE). See the [upstream version](https://github.com/modelcontextprotocol/csharp-sdk/blob/v2.2.0/LICENSE).

The Dockerfile builds on Microsoft .NET/Ubuntu images and installs gss-ntlmssp, ca-certificates and curl with their transitive system packages. Their licenses are not replaced by this project license. A distributor publishing a built image must retain its actual /usr/share/doc copyright/license files and upstream image notices, inventory resolved package versions, and satisfy their source/notice obligations. The source-only package does not include those binaries.

Microsoft Exchange, Outlook, Windows, Keycloak, OpenAI, ChatGPT and other product names belong to their respective owners. This is an independent integration and does not claim their endorsement.
