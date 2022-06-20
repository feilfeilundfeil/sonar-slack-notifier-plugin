package com.koant.sonar.slacknotifier.extension.task;

import static java.lang.String.format;
import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.seratch.jslack.api.model.Attachment;
import com.github.seratch.jslack.api.model.Field;
import com.github.seratch.jslack.api.webhook.Payload;
import com.koant.sonar.slacknotifier.common.component.ProjectConfig;
import com.koant.sonar.slacknotifier.common.component.ProjectConfigBuilder;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.RandomStringUtils;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.sonar.api.ce.posttask.Branch;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * Created by ak on 18/10/16.
 * Modified by poznachowski
 */
@Slf4j
public class ProjectAnalysisPayloadBuilderTest {
    private static final boolean QG_FAIL_ONLY = true;
    private CaptorPostProjectAnalysisTask postProjectAnalysisTask;

    private Locale defaultLocale;

    @Before
    public void before() {
        this.postProjectAnalysisTask = new CaptorPostProjectAnalysisTask();

        // org/sonar/l10n/core.properties
        this.defaultLocale = Locale.getDefault();
        Locale.setDefault(Locale.US);
    }

    @After
    public void after(){
        Locale.setDefault(this.defaultLocale);

    }

    @Test
    public void execute_is_passed_a_non_null_ProjectAnalysis_object() {
        Analyses.simple(this.postProjectAnalysisTask);
        assertThat(this.postProjectAnalysisTask.getProjectAnalysis()).isNotNull();
    }

    @Test
    public void testPayloadBuilder() throws JsonProcessingException {
        Analyses.qualityGateOk4Conditions(this.postProjectAnalysisTask);
        final ProjectConfig projectConfig = new ProjectConfigBuilder().setProjectHook("hook")
                                                                .setProjectKeyOrRegExp("key")
                                                                .setSlackChannel("#channel")
                                                                .setNotify("")
                                                                .setQgFailOnly(false).build();
        final Payload payload = ProjectAnalysisPayloadBuilder.of(this.postProjectAnalysisTask.getProjectAnalysis())
                .projectConfig(projectConfig)
                .projectUrl("http://localhist:9000/dashboard?id=project:key")
                .username("CKSSlackNotifier")
                .build();

        log.info("Generated : \n{}", new ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(payload));
        log.info("Expected : \n{}", new ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(this.expected()));

        assertThat(payload).isEqualTo(this.expected());
    }

    private Payload expected() {
        final List<Attachment> attachments = new ArrayList<>();
        final List<Field> fields = new ArrayList<>();
        fields.add(Field.builder()
                .title("new_vulnerabilities: OK")
                .value("0, error if >0")
                .valueShortEnough(false)
                .build());
        fields.add(Field.builder()
                .title("new_bugs: ERROR")
                .value("1, error if >0")
                .valueShortEnough(false)
                .build());
        fields.add(Field.builder()
                .title("new_sqale_debt_ratio: OK")
                .value("0.01%, error if >10.0%")
                .valueShortEnough(false)
                .build());
        fields.add(Field.builder()
                .title("new_coverage: ERROR")
                .value("75.51%, error if <80.0%")
                .valueShortEnough(false)
                .build());

        attachments.add(Attachment.builder()
                .fields(fields)
                .color("good")
                .build());
        return Payload.builder()
                .text("Project <http://localhist:9000/dashboard?id=project:key|Sonar Project Name> analyzed."
                    + format("%nQuality gate status: OK"))
                .channel("#channel")
                .username("CKSSlackNotifier")
                .attachments(attachments)
                .build();
    }

    @Test
    public void shouldShowOnlyExceededConditionsIfProjectConfigReportOnlyOnFailedQualityGateWay() {
        Analyses.qualityGateError2Of3ConditionsFailed(this.postProjectAnalysisTask);
        final ProjectConfig projectConfig = new ProjectConfigBuilder().setProjectHook("hook").setProjectKeyOrRegExp("key")
                                                                .setSlackChannel("#channel").setNotify("")
                                                                .setQgFailOnly(QG_FAIL_ONLY).build();
        final Payload payload = ProjectAnalysisPayloadBuilder.of(this.postProjectAnalysisTask.getProjectAnalysis())
                .projectConfig(projectConfig)
                .projectUrl("http://localhist:9000/dashboard?id=project:key")
                .username("CKSSlackNotifier")
                .build();

        assertThat(payload.getAttachments())
                .hasSize(1)
                .flatExtracting(Attachment::getFields)
                .hasSize(2)
                .extracting(Field::getTitle)
                .contains("functions: WARN", "violations: ERROR");
    }

    @Test
    public void buildPayloadWithoutQualityGateWay() {
        Analyses.noQualityGate(this.postProjectAnalysisTask);
        final ProjectConfig projectConfig = new ProjectConfigBuilder().setProjectHook("hook").setProjectKeyOrRegExp("key")
                                                                .setSlackChannel("#channel").setNotify("")
                                                                .setQgFailOnly(false).build();
        final Payload payload = ProjectAnalysisPayloadBuilder.of(this.postProjectAnalysisTask.getProjectAnalysis())
                .projectConfig(projectConfig)
                .projectUrl("http://localhist:9000/dashboard?id=project:key")
                .username("CKSSlackNotifier")
                .build();

        assertThat(payload.getAttachments()).isNull();
        assertThat(payload.getText()).doesNotContain("Quality Gate status");
    }

    @Test
    public void buildPayloadWithoutNotify() {
        Analyses.noQualityGate(this.postProjectAnalysisTask);
        final ProjectConfig projectConfig = new ProjectConfigBuilder().setProjectHook("key").setProjectKeyOrRegExp("#channel")
                                                                .setSlackChannel("").setNotify("").setQgFailOnly(false)
                                                                .build();
        final Payload payload = ProjectAnalysisPayloadBuilder.of(this.postProjectAnalysisTask.getProjectAnalysis())
            .projectConfig(projectConfig)
            .projectUrl("http://localhist:9000/dashboard?id=project:key")
            .username("CKSSlackNotifier")
            .build();

        assertThat(payload.getAttachments()).isNull();
        assertThat(payload.getText()).doesNotContain("here");
    }

    @Test
    public void build_noBranch_notifyPrefixAppended(){
        Analyses.noQualityGate(this.postProjectAnalysisTask);
        final String notify = RandomStringUtils.random(10);
        final Payload payload = ProjectAnalysisPayloadBuilder.of(this.postProjectAnalysisTask.getProjectAnalysis())
            .projectConfig(new ProjectConfigBuilder().setProjectHook("hook").setProjectKeyOrRegExp("kew")
                                                     .setSlackChannel("#channel").setNotify(notify).setQgFailOnly(false).build())
            .projectUrl("http://localhost:9000/dashboard?id=project:key")
            .username("CKSSlackNotifier")
            .build();
        Assert.assertEquals(
            format(
                "<%s> Project <http://localhost:9000/dashboard?id=project:key|Sonar Project Name> analyzed.", notify
            ),
            payload.getText()
        );
    }

    @Test
    public void build_mainBranch_branchNotAddedToMessage(){

        final String branchName = "my-branch";
        final boolean isMain = true;

        Analyses.withBranch(this.postProjectAnalysisTask, this.newBranch(branchName, isMain));
        final Payload payload = ProjectAnalysisPayloadBuilder.of(this.postProjectAnalysisTask.getProjectAnalysis())
            .projectConfig(new ProjectConfigBuilder().setProjectHook("key").setProjectKeyOrRegExp("#channel").setSlackChannel(
                "").setNotify("").setQgFailOnly(false).build())
            .projectUrl("http://localhost:9000/dashboard?id=project:key")
            .username("CKSSlackNotifier")
            .includeBranch(true)
            .build();
        Assert.assertEquals(
            "Project <http://localhost:9000/dashboard?id=project:key|Sonar Project Name> analyzed.",
            payload.getText()
        );
    }

    @Test
    public void build_withIncludeBranchTrue_branchAddedToMessage(){

        final String branchName = RandomStringUtils.random(10);
        Analyses.withBranch(this.postProjectAnalysisTask, this.newBranch(branchName, false));
        final Payload payload = ProjectAnalysisPayloadBuilder.of(this.postProjectAnalysisTask.getProjectAnalysis())
            .projectConfig(new ProjectConfigBuilder().setProjectHook("key").setProjectKeyOrRegExp("#channel").setSlackChannel(
                "").setNotify("").setQgFailOnly(false).build())
            .projectUrl("http://localhost:9000/dashboard?id=project:key")
            .username("CKSSlackNotifier")
            .includeBranch(true)
            .build();
        Assert.assertEquals(format("Project <http://localhost:9000/dashboard?id=project:key|Sonar Project Name> analyzed for branch [%s].",
            branchName), payload.getText());
    }

    @Test
    public void build_enabledButNoBranchPresent_branchNotAddedToMessage(){

        Analyses.simple(this.postProjectAnalysisTask);
        final Payload payload = ProjectAnalysisPayloadBuilder.of(this.postProjectAnalysisTask.getProjectAnalysis())
            .projectConfig(new ProjectConfigBuilder().setProjectHook("key").setProjectKeyOrRegExp("#channel").setSlackChannel(
                "").setNotify("").setQgFailOnly(false).build())
            .projectUrl("http://localhost:9000/dashboard?id=project:key")
            .username("CKSSlackNotifier")
            .includeBranch(true)
            .build();
        Assert.assertEquals(format("Project <http://localhost:9000/dashboard?id=project:key|Sonar Project Name> analyzed.%nQuality gate status: OK"), payload.getText());
    }

    private Branch newBranch(final String name, final boolean isMain) {

        return new Branch() {

                  @Override
                  public boolean isMain() {

                      return isMain;
                  }

                  @Override
                  public Optional<String> getName() {

                      return Optional.of(name);
                  }

                  @Override
                  public Type getType() {

                      return Type.BRANCH;
                  }
              };
    }
}
