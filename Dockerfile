# syntax=docker/dockerfile:1
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY clash-converter-csharp.csproj ./
RUN dotnet restore clash-converter-csharp.csproj
COPY . .
RUN dotnet publish clash-converter-csharp.csproj -c Release -o /app

FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS final
WORKDIR /app
COPY --from=build /app .
ENV PORT=5000
EXPOSE 5000
ENTRYPOINT ["dotnet", "clash-converter.dll"]
