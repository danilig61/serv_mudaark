from django import forms


class UploadFileForm(forms.Form):
    file = forms.FileField(required=False, label='Файл')
    url = forms.URLField(required=False, label='URL')
    name = forms.CharField(max_length=100, label='Имя файла')
    speakers = forms.IntegerField(label='Количество спикеров')
    language = forms.ChoiceField(choices=[('Russian', 'Русский')], label='Язык')
    analyze_text = forms.BooleanField(required=False, label="Анализировать текст")
