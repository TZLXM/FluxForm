namespace FluxForm.Core.Models;

public class ProgressInfo
{
    public Guid TaskId { get; set; }
    public ConversionStatus Status { get; set; }
    public double Percent { get; set; }
    public string Message { get; set; } = string.Empty;
    public TimeSpan? EstimatedRemaining { get; set; }
}
