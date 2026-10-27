FROM mcr.microsoft.com/dotnet/sdk:10.0-noble@sha256:0eeb52c76e35a5431ca707ad2bc75e38006a05393045d8532ae44c15d9474523 AS build
WORKDIR /source
COPY global.json Directory.Build.props NuGet.Config ./
COPY src/Company.ExchangeMcp/Company.ExchangeMcp.csproj src/Company.ExchangeMcp/packages.lock.json src/Company.ExchangeMcp/
RUN dotnet restore src/Company.ExchangeMcp/Company.ExchangeMcp.csproj --locked-mode --configfile NuGet.Config
COPY src/Company.ExchangeMcp/ src/Company.ExchangeMcp/
RUN dotnet publish src/Company.ExchangeMcp/Company.ExchangeMcp.csproj --no-restore -c Release -o /out /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0-noble@sha256:8af87eba5e7cdafb1514d7388be287365da97c132509e84dfe252ffd552398ca AS runtime
USER root
# .NET's Linux NTLM authentication requires the native GSS-NTLM mechanism.
RUN apt-get update && apt-get install -y --no-install-recommends gss-ntlmssp ca-certificates curl && rm -rf /var/lib/apt/lists/*
COPY certs/ /usr/local/share/ca-certificates/operator/
RUN update-ca-certificates
WORKDIR /app
COPY --from=build /out/ ./
RUN mkdir -p /app/audit && chown "$APP_UID:$APP_UID" /app/audit && chmod 700 /app/audit
ENV ASPNETCORE_HTTP_PORTS=8080 DOTNET_EnableDiagnostics=0
USER $APP_UID
EXPOSE 8080
ENTRYPOINT ["dotnet", "Company.ExchangeMcp.dll"]
