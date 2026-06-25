using System.Collections.Generic;
using FluxForm.Core.Models;
using FluxForm.WPF.ViewModels;

namespace FluxForm.Tests;

public class MainViewModelBatchFlowTests
{
    [Fact]
    public void TryAddFile_WhenCategoryMatches_AddsFileAndPreservesBatchConfiguration()
    {
        var batch = new PendingBatchViewModel();

        var firstAccepted = batch.TryAddFile("C:/media/intro.mp4", ConversionCategory.Video, 1024, "1080p H.264");
        batch.OutputFormat = "mp4";
        batch.OutputDirectory = "C:/output";
        batch.SetOption("crf", "23");

        var secondAccepted = batch.TryAddFile("C:/media/trailer.mkv", ConversionCategory.Video, 2048, "4K HEVC");

        Assert.True(firstAccepted);
        Assert.True(secondAccepted);
        Assert.Equal(ConversionCategory.Video, batch.Category);
        Assert.Equal("mp4", batch.OutputFormat);
        Assert.Equal("C:/output", batch.OutputDirectory);
        Assert.Equal("23", batch.Options["crf"]);
        Assert.Collection(
            batch.Files,
            file => AssertPendingFile(file, "C:/media/intro.mp4", "intro.mp4", 1024, "1080p H.264"),
            file => AssertPendingFile(file, "C:/media/trailer.mkv", "trailer.mkv", 2048, "4K HEVC"));
        Assert.Equal(string.Empty, batch.ValidationMessage);
    }

    [Fact]
    public void TryAddFile_WhenCategoryMixed_RejectsFileAndSetsChineseValidationMessage()
    {
        var batch = new PendingBatchViewModel();
        batch.TryAddFile("C:/media/intro.mp4", ConversionCategory.Video, 1024, "1080p H.264");

        var accepted = batch.TryAddFile("C:/media/song.mp3", ConversionCategory.Audio, 512, "320kbps");

        Assert.False(accepted);
        Assert.Single(batch.Files);
        Assert.Equal(ConversionCategory.Video, batch.Category);
        Assert.Equal("当前批次只支持同类型文件，请分别添加视频、音频、图片或文档文件。", batch.ValidationMessage);
    }

    [Fact]
    public void SetOption_UsesCaseInsensitiveDictionaryAndOverwritesExistingValue()
    {
        var batch = new PendingBatchViewModel();

        batch.SetOption("CRF", "23");
        batch.SetOption("crf", "19");

        Assert.Single(batch.Options);
        Assert.True(batch.Options.ContainsKey("CRF"));
        Assert.Equal("19", batch.Options["crf"]);
    }

    [Fact]
    public void Reset_ClearsFilesCategoryOutputOptionsAndValidationState()
    {
        var batch = new PendingBatchViewModel();
        batch.TryAddFile("C:/docs/spec.pdf", ConversionCategory.Document, 4096, "A4 PDF");
        batch.OutputFormat = "pdf";
        batch.OutputDirectory = "D:/exports";
        batch.SetOption("dpi", "300");
        batch.TryAddFile("C:/media/song.mp3", ConversionCategory.Audio, 512, "320kbps");

        batch.Reset();

        Assert.Empty(batch.Files);
        Assert.Null(batch.Category);
        Assert.Equal(string.Empty, batch.OutputFormat);
        Assert.Equal(string.Empty, batch.OutputDirectory);
        Assert.Empty(batch.Options);
        Assert.Equal(string.Empty, batch.ValidationMessage);
    }

    private static void AssertPendingFile(
        PendingBatchFileViewModel file,
        string inputPath,
        string fileName,
        long fileSizeBytes,
        string summary)
    {
        Assert.Equal(inputPath, file.InputPath);
        Assert.Equal(fileName, file.FileName);
        Assert.Equal(fileSizeBytes, file.FileSizeBytes);
        Assert.Equal(summary, file.Summary);
    }
}
