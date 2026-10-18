using System.Windows;
using NetGuard.Desktop.ViewModels;

namespace NetGuard.Desktop;

public partial class MainWindow : Window
{
    public MainWindow(MainViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
    }
}
