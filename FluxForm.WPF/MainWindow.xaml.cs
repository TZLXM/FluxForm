using System.Windows;
using FluxForm.WPF.ViewModels;
using Wpf.Ui.Controls;

namespace FluxForm.WPF;

public partial class MainWindow : FluentWindow
{
    public MainWindow()
    {
        InitializeComponent();
        DataContext = FindResource("ViewModel");
    }

    private MainViewModel? ViewModel => DataContext as MainViewModel;

    private void Window_PreviewDragEnter(object sender, DragEventArgs e)
    {
        if (e.Data.GetDataPresent(DataFormats.FileDrop) && ViewModel?.IsBusy != true)
        {
            e.Effects = DragDropEffects.Copy;
            DropOverlay.Visibility = Visibility.Visible;
        }
        else
        {
            e.Effects = DragDropEffects.None;
        }
    }

    private void Window_PreviewDragOver(object sender, DragEventArgs e)
    {
        if (e.Data.GetDataPresent(DataFormats.FileDrop) && ViewModel?.IsBusy != true)
        {
            e.Effects = DragDropEffects.Copy;
            DropOverlay.Visibility = Visibility.Visible;
        }
        else
        {
            e.Effects = DragDropEffects.None;
        }
    }

    private void Window_PreviewDragLeave(object sender, DragEventArgs e)
    {
        DropOverlay.Visibility = Visibility.Collapsed;
    }

    private void Window_PreviewDrop(object sender, DragEventArgs e)
    {
        DropOverlay.Visibility = Visibility.Collapsed;

        if (e.Data.GetDataPresent(DataFormats.FileDrop) && ViewModel is { IsBusy: false } vm)
        {
            var files = (string[])e.Data.GetData(DataFormats.FileDrop)!;
            vm.AddFiles(files);
        }

        e.Handled = true;
    }

}
