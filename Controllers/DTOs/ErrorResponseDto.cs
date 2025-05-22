namespace stocktaking_auth.Models;

public class ErrorResponseDTO
{
    public string Message { get; set; } = string.Empty;
    public static ErrorResponseDTO EmailAlreadyExists()
  {
    return new ErrorResponseDTO
    {
      Message = "Email already exists",
    };
  }

    public static ErrorResponseDTO InvalidCredentials()
    {
        return new ErrorResponseDTO
        {
            Message = "Invalid credentials",
        };
    }

    public static ErrorResponseDTO MissingTokens()
    {
        return new ErrorResponseDTO
        {
            Message = "Missing tokens",
        };
    }

    public static ErrorResponseDTO InvalidAccessToken()
    {
        return new ErrorResponseDTO
        {
            Message = "Invalid access token",
        };
    }

    public static ErrorResponseDTO InvalidRefreshToken()
    {
        return new ErrorResponseDTO
        {
            Message = "Invalid refresh token",
        };
    }

    public static ErrorResponseDTO UserNotFound()
    {
        return new ErrorResponseDTO
        {
            Message = "User not found",
        };
    }

    public static ErrorResponseDTO Unauthorized()
    {
        return new ErrorResponseDTO
        {
            Message = "Unauthorized",
        };
    }

    public static ErrorResponseDTO ValidationError(string message)
    {
        return new ErrorResponseDTO
        {
            Message = message,
        };
    }
}
