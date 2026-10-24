from django import forms
from django.contrib.auth import password_validation
from django.contrib.auth.forms import AuthenticationForm
from .models import Invitation, Operator


class StyledFormMixin:
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs.setdefault("class", "field-input")


class OperatorAuthenticationForm(StyledFormMixin, AuthenticationForm):
    pass


class ClaimForm(StyledFormMixin, forms.Form):
    username = forms.CharField(max_length=150, initial="admin")
    password = forms.CharField(widget=forms.PasswordInput, min_length=12)
    password_confirm = forms.CharField(widget=forms.PasswordInput, label="Confirm password")

    def clean_username(self):
        username = self.cleaned_data["username"].strip()
        if Operator.objects.filter(username__iexact=username).exists():
            raise forms.ValidationError("That username is already in use.")
        return username

    def clean(self):
        data = super().clean()
        if data.get("password") != data.get("password_confirm"):
            self.add_error("password_confirm", "Passwords do not match.")
        if data.get("password"):
            password_validation.validate_password(data["password"])
        return data


class InvitationForm(StyledFormMixin, forms.ModelForm):
    class Meta:
        model = Invitation
        fields = ["username", "email", "role"]

    def clean_username(self):
        username = self.cleaned_data["username"].strip()
        if Operator.objects.filter(username__iexact=username).exists():
            raise forms.ValidationError("An operator with this username already exists.")
        return username


class InvitationAcceptForm(ClaimForm):
    username = forms.CharField(max_length=150, disabled=True)
