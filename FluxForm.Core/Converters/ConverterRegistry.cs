using FluxForm.Core.Models;

namespace FluxForm.Core.Converters;

public class ConverterRegistry
{
    private readonly List<IConverter> _converters = new();

    public void Register(IConverter converter)
    {
        _converters.Add(converter);
    }

    public IConverter? FindConverter(string inputExtension, string outputExtension)
    {
        return _converters.FirstOrDefault(c => c.CanConvert(inputExtension, outputExtension));
    }

    public IEnumerable<IConverter> GetConverters(ConversionCategory? category = null)
    {
        return category == null ? _converters : _converters.Where(c => c.Category == category);
    }

    public IReadOnlyList<FormatInfo> GetSupportedFormats(ConversionCategory? category = null)
    {
        var formats = new List<FormatInfo>();
        foreach (var converter in GetConverters(category))
        {
            foreach (var ext in converter.SupportedOutputFormats)
            {
                formats.Add(new FormatInfo
                {
                    Extension = ext,
                    Name = ext.ToUpperInvariant(),
                    Category = converter.Category
                });
            }
        }
        return formats.GroupBy(f => new { f.Extension, f.Category })
                      .Select(g => g.First())
                      .OrderBy(f => f.Category)
                      .ThenBy(f => f.Extension)
                      .ToList();
    }
}
