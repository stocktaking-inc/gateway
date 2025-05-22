FROM mcr.microsoft.com/dotnet/sdk:9.0-alpine AS build
WORKDIR /src

COPY *.csproj ./
RUN dotnet restore

COPY . ./
RUN dotnet publish -c Release -o /app/publish \
    -p:PublishReadyToRun=true \
    -p:PublishSingleFile=false \
    --self-contained false \
    -r linux-musl-x64

FROM mcr.microsoft.com/dotnet/aspnet:9.0-alpine
WORKDIR /app

RUN apk add --no-cache libstdc++

COPY --from=build /app/publish ./

EXPOSE 5100
ENTRYPOINT ["dotnet", "stocktaking-auth.dll"]
