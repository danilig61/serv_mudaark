from rest_framework import serializers
from .models import File


class FileSerializer(serializers.ModelSerializer):
    created_at_formatted = serializers.SerializerMethodField()

    class Meta:
        model = File
        fields = '__all__'

    def get_created_at_formatted(self, obj):
        return obj.created_at.strftime('%d.%m.%Y')

    def create(self, validated_data):
        return File.objects.create(**validated_data)

    def update(self, instance, validated_data):
        instance.name = validated_data.get('name', instance.name)
        instance.speakers = validated_data.get('speakers', instance.speakers)
        instance.language = validated_data.get('language', instance.language)
        instance.status = validated_data.get('status', instance.status)
        instance.transcription = validated_data.get('transcription', instance.transcription)
        instance.analysis_result = validated_data.get('analysis_result', instance.analysis_result)
        instance.save()
        return instance


class UploadFileSerializer(serializers.Serializer):
    file = serializers.FileField(required=False)
    url = serializers.URLField(required=False)
    name = serializers.CharField(max_length=255)
    speakers = serializers.IntegerField()
    language = serializers.CharField(max_length=100)
    analyze_text = serializers.BooleanField(required=False, default=False)