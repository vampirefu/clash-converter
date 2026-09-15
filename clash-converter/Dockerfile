# 阶段结构遵循 VS 容器调试契约：
#   base   —— 运行时基础镜像（F5 调试容器从此阶段运行，EXPOSE 声明端口）
#   build  —— SDK 编译阶段（restore + publish）
#   final  —— 生产镜像（FROM base + 发布产物）
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
WORKDIR /app
EXPOSE 8080

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY clash-converter-csharp.csproj ./
RUN dotnet restore clash-converter-csharp.csproj
COPY . .
RUN dotnet publish clash-converter-csharp.csproj -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=build /app/publish .
# 容器内监听 8080（ASP.NET 容器惯例，与 EXPOSE 一致；
# 未设置 ASPNETCORE_URLS 时由 Program.cs 的 PORT 逻辑生效）
ENV PORT=8080
ENTRYPOINT ["dotnet", "clash-converter.dll"]
