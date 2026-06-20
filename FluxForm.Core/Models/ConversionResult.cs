namespace FluxForm.Core.Models;

public enum ConversionStatus
{
    Pending,
    Running,
    Succeeded,
    Failed,
    Cancelled
}

public class ConversionResult
{
    public Guid TaskId { get; set; }
    public ConversionStatus Status { get; set; }
    public string? OutputPath { get; set; }
    public string? ErrorMessage { get; set; }
    public TimeSpan Duration { get; set; }

    public static ConversionResult Success(Guid taskId, string outputPath, TimeSpan duration)
        => new() { TaskId = taskId, Status = ConversionStatus.Succeeded, OutputPath = outputPath, Duration = duration };

    public static ConversionResult Failure(Guid taskId, string error, TimeSpan duration)
        => new() { TaskId = taskId, Status = ConversionStatus.Failed, ErrorMessage = error, Duration = duration };

    public static ConversionResult Cancelled(Guid taskId)
        => new() { TaskId = taskId, Status = ConversionStatus.Cancelled };
}
